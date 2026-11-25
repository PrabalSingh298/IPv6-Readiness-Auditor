"""Measurement-scoped SOCKS5 TCP proxy with explicit upstream socket families."""

import asyncio
import ipaddress
import math
import socket
import sys
from collections import deque
from concurrent.futures import Future
from dataclasses import dataclass
from threading import Lock, Thread


_FAMILIES = {"ipv4_only": socket.AF_INET, "ipv6_only": socket.AF_INET6}
# Windows select() accepts 512 sockets. Each tunnel can use two.
_WINDOWS_CLIENT_LIMIT = 250
_ServerHandle = tuple[asyncio.AbstractEventLoop, asyncio.Event, int]
_Streams = tuple[asyncio.StreamReader, asyncio.StreamWriter]


@dataclass(frozen=True)
class ConnectionAttempt:
    hostname: str
    port: int
    mode: str
    attempted_ip: str | None = None
    remote_ip: str | None = None
    upstream_family: str | None = None
    success: bool = False
    failure_reason: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class HostnameResolution:
    addresses: tuple[tuple[int, tuple], ...] = ()
    failure_reason: str | None = None
    detail: str | None = None


class IPFamilyProxy:
    """Use from a synchronous caller, with one lifecycle per browser run."""

    def __init__(
        self,
        mode: str = "dual_stack",
        *,
        connect_timeout: float = 5.0,
        idle_timeout: float = 60.0,
        history_limit: int = 2000,
    ) -> None:
        if mode != "dual_stack" and mode not in _FAMILIES:
            raise ValueError("mode must be dual_stack, ipv4_only, or ipv6_only")
        if any(not math.isfinite(value) or value <= 0 for value in (connect_timeout, idle_timeout)):
            raise ValueError("timeouts must be finite and positive")
        if history_limit < 1:
            raise ValueError("history_limit must be positive")
        self._mode = mode
        self._family = _FAMILIES.get(mode)
        self._connect_timeout = connect_timeout
        self._idle_timeout = idle_timeout
        self._attempts: deque[ConnectionAttempt] = deque(maxlen=history_limit)
        self._attempt_lock = Lock()
        self._lookups: dict[str, asyncio.Task[HostnameResolution]] = {}
        self._resolutions: dict[str, HostnameResolution] = {}
        self._thread: Thread | None = None
        self._server: _ServerHandle | None = None

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def is_running(self) -> bool:
        """True while a restricted mode's listener is running."""
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    @property
    def connection_attempts(self) -> tuple[ConnectionAttempt, ...]:
        """Snapshot of the most recent DNS outcomes and TCP attempts."""
        with self._attempt_lock:
            return tuple(self._attempts)

    @property
    def hostname_resolutions(self) -> dict[str, HostnameResolution]:
        with self._attempt_lock:
            return dict(self._resolutions)

    def start(self) -> "IPFamilyProxy":
        if self._family is None or self.is_running:
            return self
        with self._attempt_lock:
            self._attempts.clear()
            self._resolutions.clear()
        self._lookups.clear()
        ready: Future[_ServerHandle] = Future()
        self._thread = Thread(target=self._run, args=(ready,), name="ip-family-proxy", daemon=True)
        self._thread.start()
        try:
            self._server = ready.result()
        except BaseException:
            def stop_after_binding(result: Future[_ServerHandle]) -> None:
                if result.exception() is None:
                    loop, stopping, _ = result.result()
                    loop.call_soon_threadsafe(stopping.set)

            ready.add_done_callback(stop_after_binding)
            self._thread = None
            raise
        return self

    def stop(self) -> None:
        if self.is_running:
            loop, stopping, _ = self._server
            loop.call_soon_threadsafe(stopping.set)
            self._thread.join()
        self._server = None
        self._thread = None

    def __enter__(self) -> "IPFamilyProxy":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def playwright_launch_options(self) -> dict:
        """Keyword arguments for Playwright Chromium's launch method."""
        if self._family is None:
            return {}
        if not self.is_running:
            raise RuntimeError("Start the IP family proxy before launching Chromium")
        port = self._server[2]
        return {
            "proxy": {"server": f"socks5://127.0.0.1:{port}", "bypass": "<-loopback>"},
            "args": [
                "--disable-quic",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            ],
        }

    def _run(self, ready: Future[_ServerHandle]) -> None:
        try:
            # On Windows, the proactor can leave a transport attached if socket
            # shutdown raises after Chromium resets a pooled connection.
            loop = asyncio.SelectorEventLoop()
            try:
                loop.run_until_complete(self._serve(ready))
            finally:
                loop.close()
        except BaseException as error:
            if ready.done():
                raise
            ready.set_exception(error)

    async def _serve(self, ready: Future[_ServerHandle]) -> None:
        stopping = asyncio.Event()
        clients: dict[asyncio.Task, asyncio.StreamWriter] = {}

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if stopping.is_set() or (sys.platform == "win32" and len(clients) >= _WINDOWS_CLIENT_LIMIT):
                writer.transport.abort()
                return
            task = asyncio.create_task(self._handle_client(reader, writer))
            clients[task] = writer
            task.add_done_callback(clients.pop)

        server = await asyncio.start_server(accept, "127.0.0.1", 0, family=socket.AF_INET)
        try:
            ready.set_result((asyncio.get_running_loop(), stopping, server.sockets[0].getsockname()[1]))
            await stopping.wait()
        finally:
            server.close()
            pending = tuple(clients)
            for task, writer in clients.items():
                task.cancel()
                writer.transport.abort()
            await asyncio.gather(*pending, return_exceptions=True)
            for lookup in self._lookups.values():
                lookup.cancel()
            await asyncio.gather(*self._lookups.values(), return_exceptions=True)
            await server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream = None
        try:
            async with asyncio.timeout(self._connect_timeout):
                version, methods = await reader.readexactly(2)
                if version != 5:
                    return
                if 0 not in await reader.readexactly(methods):
                    await _send(writer, b"\x05\xff")
                    return
                await _send(writer, b"\x05\x00")
                version, command, reserved, address_type = await reader.readexactly(4)
                if version != 5 or reserved != 0:
                    return
                if command != 1:  # CONNECT
                    await _reply(writer, 7)
                    return
                if address_type in (1, 4):
                    packed = await reader.readexactly(4 if address_type == 1 else 16)
                    hostname = str(ipaddress.ip_address(packed))
                elif address_type == 3:
                    length = (await reader.readexactly(1))[0]
                    hostname = (await reader.readexactly(length)).decode("ascii")
                    if not hostname or "\x00" in hostname:
                        return
                else:
                    await _reply(writer, 8)
                    return
                port = int.from_bytes(await reader.readexactly(2), "big")

            upstream, status = await self._connect(hostname, port)
            if upstream is None:
                await _reply(writer, status)
                return
            upstream_reader, upstream_writer = upstream
            await _reply(writer, 0, upstream_writer.get_extra_info("sockname"))
            await self._relay(reader, writer, upstream_reader, upstream_writer)
        except (OSError, EOFError, UnicodeError, ValueError):
            # Disconnects, malformed handshakes and idle tunnels are local to this client.
            pass
        finally:
            writers = (writer,) if upstream is None else (writer, upstream[1])
            for stream in writers:
                stream.close()
            try:
                async with asyncio.timeout(self._connect_timeout):
                    await asyncio.gather(*(stream.wait_closed() for stream in writers), return_exceptions=True)
            except TimeoutError:
                for stream in writers:
                    stream.transport.abort()
            except asyncio.CancelledError:
                for stream in writers:
                    stream.transport.abort()
                raise

    def _record(self, hostname: str, port: int, **fields: object) -> None:
        with self._attempt_lock:
            self._attempts.append(ConnectionAttempt(hostname, port, self.mode, **fields))

    async def _resolve(self, hostname: str) -> HostnameResolution:
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(self._connect_timeout):
                results = await loop.getaddrinfo(hostname, 0, type=socket.SOCK_STREAM)
            resolution = HostnameResolution(tuple((family, address) for family, _, _, _, address in results))
        except TimeoutError:
            resolution = HostnameResolution(failure_reason="dns_timeout")
        except (OSError, UnicodeError) as error:
            resolution = HostnameResolution(failure_reason="dns_failure", detail=str(error))
        with self._attempt_lock:
            self._resolutions[hostname] = resolution
        return resolution

    async def _connect(self, hostname: str, port: int) -> tuple[_Streams | None, int]:
        key = hostname.lower()
        lookup = self._lookups.get(key)
        if lookup is None:
            with self._attempt_lock:
                self._resolutions[key] = HostnameResolution(failure_reason="dns_cancelled")
            lookup = self._lookups[key] = asyncio.create_task(self._resolve(key))
        resolution = await asyncio.shield(lookup)
        if resolution.failure_reason:
            self._record(hostname, port, failure_reason=resolution.failure_reason, detail=resolution.detail)
            return None, 4

        addresses = dict.fromkeys(
            (address[0], port, *address[2:]) for family, address in resolution.addresses
            if family == self._family
            and (family != socket.AF_INET6 or ipaddress.IPv6Address(address[0]).ipv4_mapped is None)
        )
        if not addresses:
            self._record(hostname, port, failure_reason="address_family_unavailable")
            return None, 4

        status = 1
        for address in addresses:
            try:
                upstream = await self._open_upstream(address)
            except OSError as error:
                reason = "connection_timeout" if isinstance(error, TimeoutError) else "connection_failure"
                self._record(hostname, port, attempted_ip=address[0], failure_reason=reason, detail=str(error))
                status = 5 if isinstance(error, ConnectionRefusedError) else 4
                continue

            writer = upstream[1]
            peer = writer.get_extra_info("peername")
            connected_family = writer.get_extra_info("socket").family
            self._record(
                hostname, port, attempted_ip=address[0], remote_ip=peer[0] if peer else None,
                upstream_family="ipv4" if connected_family == socket.AF_INET else "ipv6", success=True,
            )
            return upstream, 0
        return None, status

    async def _open_upstream(self, address: tuple) -> _Streams:
        upstream = socket.socket(self._family, socket.SOCK_STREAM)
        try:
            if self._family == socket.AF_INET6:
                upstream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            upstream.setblocking(False)
            async with asyncio.timeout(self._connect_timeout):
                await asyncio.get_running_loop().sock_connect(upstream, address)
            return await asyncio.open_connection(sock=upstream)
        except BaseException:
            upstream.close()
            raise

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(self._idle_timeout) as idle:
            async def copy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                while data := await reader.read(65536):
                    idle.reschedule(loop.time() + self._idle_timeout)
                    await _send(writer, data)
                writer.write_eof()

            tasks = (
                asyncio.create_task(copy(client_reader, upstream_writer)),
                asyncio.create_task(copy(upstream_reader, client_writer)),
            )
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)


async def _send(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    await writer.drain()


async def _reply(writer: asyncio.StreamWriter, status: int, bound: tuple = ("0.0.0.0", 0)) -> None:
    address = ipaddress.ip_address(bound[0])
    address_type = 1 if address.version == 4 else 4
    await _send(writer, bytes((5, status, 0, address_type)) + address.packed + bound[1].to_bytes(2, "big"))
