import asyncio
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Barrier, BrokenBarrierError, Thread
from unittest.mock import patch
from urllib.parse import urlsplit

from backend.measurement.ip_family_proxy import IPFamilyProxy


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        content = {
            "/": ("text/html", b'<link rel="stylesheet" href="/style.css">'
                  b'<script defer src="/app.js"></script><p id="result"></p>'),
            "/style.css": ("text/css", b"p { color: rgb(1, 2, 3); }"),
            "/app.js": ("text/javascript", b"fetch('/api').then(r => r.text()).then("
                        b"text => document.querySelector('#result').textContent = text);"),
            "/api": ("text/plain", b"via origin"),
        }
        if self.server.resource_barrier and self.path in ("/style.css", "/app.js"):
            try:
                self.server.resource_barrier.wait(timeout=5)
            except BrokenBarrierError:
                self.send_error(503)
                return
        mime, body = content.get(self.path, ("text/plain", b"ok"))
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


@contextmanager
def origin(host, port=0, *, tls=None, parallel=False):
    server_type = IPv6Server if ":" in host else ThreadingHTTPServer
    with server_type((host, port), Origin) as server:
        if tls:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        server.resource_barrier = Barrier(2) if parallel else None
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join()


@contextmanager
def proxy_client(proxy):
    endpoint = urlsplit(proxy.playwright_launch_options()["proxy"]["server"])
    with socket.create_connection((endpoint.hostname, endpoint.port), timeout=3) as client:
        with client.makefile("rb") as reader:
            client.sendall(b"\x05\x01\x00")
            if reader.read(2) != b"\x05\x00":
                raise AssertionError("SOCKS5 greeting failed")
            yield client, reader


def request_connect(client, reader, host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("ascii")
        target = bytes((3, len(encoded))) + encoded
    else:
        target = bytes((1 if ip.version == 4 else 4,)) + ip.packed
    client.sendall(b"\x05\x01\x00" + target + port.to_bytes(2, "big"))
    version, status, reserved, address_type = reader.read(4)
    if (version, reserved) != (5, 0) or address_type not in (1, 4):
        raise AssertionError("Invalid SOCKS5 CONNECT response")
    reader.read(6 if address_type == 1 else 18)
    return status


@contextmanager
def fixed_dns(records):
    system_lookup = socket.getaddrinfo

    def lookup(host, port, *args, **kwargs):
        if host not in records:
            return system_lookup(host, port, *args, **kwargs)
        if records[host] is None:
            raise socket.gaierror(socket.EAI_NONAME, "test host missing")
        return [answer for ip in records[host] for answer in system_lookup(
            ip, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST,
        )]

    with patch("socket.getaddrinfo", side_effect=lookup):
        yield


class ProxyTests(unittest.TestCase):
    def test_dns_family_matrix_and_literals(self):
        records = {
            "v4.test": ["127.0.0.1"], "v6.test": ["::1"],
            "dual.test": ["::1", "127.0.0.1"], "missing.test": None,
            "mapped.test": ["::ffff:127.0.0.1"],
        }
        with origin("127.0.0.1") as port, origin("::1", port), fixed_dns(records):
            for family, expected in (("ipv4", "127.0.0.1"), ("ipv6", "::1")):
                with self.subTest(family=family), IPFamilyProxy(f"{family}_only") as proxy:
                    for host in (*records, "127.0.0.1", "::1", "::ffff:127.0.0.1"):
                        with self.subTest(host=host), proxy_client(proxy) as (client, reader):
                            allowed = host == "dual.test" or host == expected or expected in (records.get(host) or [])
                            self.assertEqual(request_connect(client, reader, host, port), 0 if allowed else 4)
                            attempt = proxy.connection_attempts[-1]
                            self.assertEqual(attempt.port, port)
                            self.assertEqual(attempt.mode, f"{family}_only")
                            self.assertEqual(attempt.success, allowed)
                            self.assertEqual(attempt.remote_ip, expected if allowed else None)
                            self.assertEqual(attempt.upstream_family, family if allowed else None)
                            if not allowed:
                                reason = "dns_failure" if host == "missing.test" else "address_family_unavailable"
                                self.assertEqual(attempt.failure_reason, reason)

    def test_same_family_retry_and_no_cross_family_fallback(self):
        records = {"retry.test": ["127.0.0.2", "::1", "127.0.0.1"], "dual.test": ["127.0.0.1", "::1"]}
        with origin("127.0.0.1") as port, fixed_dns(records):
            for mode, host, expected in (("ipv4_only", "retry.test", 0), ("ipv6_only", "dual.test", 5)):
                with self.subTest(mode=mode), IPFamilyProxy(mode) as proxy, proxy_client(proxy) as (client, reader):
                    self.assertEqual(request_connect(client, reader, host, port), expected)
                    addresses = [entry.attempted_ip for entry in proxy.connection_attempts]
                    self.assertEqual(addresses, ["127.0.0.2", "127.0.0.1"] if expected == 0 else ["::1"])
                    self.assertEqual(proxy.connection_attempts[0].failure_reason, "connection_failure")
        with origin("::1") as port, fixed_dns(records), IPFamilyProxy("ipv4_only") as proxy:
            with proxy_client(proxy) as (client, reader):
                self.assertEqual(request_connect(client, reader, "dual.test", port), 5)
            self.assertEqual([entry.attempted_ip for entry in proxy.connection_attempts], ["127.0.0.1"])

    def test_connect_timeout_does_not_fall_back(self):
        async def stalled_connect(_loop, _socket, _address):
            await asyncio.Event().wait()

        with fixed_dns({"dual.test": ["127.0.0.1", "::1"]}), patch.object(
            asyncio.SelectorEventLoop, "sock_connect", stalled_connect,
        ), IPFamilyProxy("ipv6_only", connect_timeout=1) as proxy:
            with proxy_client(proxy) as (client, reader):
                self.assertEqual(request_connect(client, reader, "dual.test", 80), 4)
            attempt, = proxy.connection_attempts
            self.assertEqual(attempt.attempted_ip, "::1")
            self.assertEqual(attempt.failure_reason, "connection_timeout")

    def test_exception_stops_listener_and_active_tunnel(self):
        proxy = IPFamilyProxy("ipv4_only")
        self.assertFalse(proxy.is_running)
        with origin("127.0.0.1") as port, self.assertRaisesRegex(RuntimeError, "measurement failed"):
            with proxy:
                self.assertTrue(proxy.is_running)
                endpoint = urlsplit(proxy.playwright_launch_options()["proxy"]["server"])
                client = socket.create_connection((endpoint.hostname, endpoint.port), timeout=3)
                self.addCleanup(client.close)
                client.sendall(b"\x05\x01\x00")
                with client.makefile("rb") as reader:
                    self.assertEqual(reader.read(2), b"\x05\x00")
                    self.assertEqual(request_connect(client, reader, "127.0.0.1", port), 0)
                raise RuntimeError("measurement failed")
        self.assertFalse(proxy.is_running)
        self.assertEqual(client.recv(1), b"")
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection((endpoint.hostname, endpoint.port), timeout=5).close()
        with proxy:
            self.assertTrue(proxy.is_running)
            self.assertEqual(proxy.connection_attempts, ())


@contextmanager
def test_tls_context():
    openssl = os.environ.get("OPENSSL") or shutil.which("openssl")
    if not openssl:
        raise unittest.SkipTest("Set OPENSSL to an OpenSSL executable to generate the local TLS certificate")
    with tempfile.TemporaryDirectory() as directory:
        cert = Path(directory) / "cert.pem"
        key = Path(directory) / "key.pem"
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=web.test", "-addext", "subjectAltName=DNS:web.test",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True, timeout=15)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        yield context


class BrowserProxyTests(unittest.TestCase):
    def test_chromium_direct_and_proxied_http_https(self):
        from playwright.sync_api import Error, sync_playwright

        with test_tls_context() as tls, sync_playwright() as playwright:
            with IPFamilyProxy("dual_stack") as proxy, origin("127.0.0.1") as port:
                self.assertEqual(proxy.playwright_launch_options(), {})
                self.assertFalse(proxy.is_running)
                browser = playwright.chromium.launch(**proxy.playwright_launch_options())
                try:
                    page = browser.new_page()
                    self.assertEqual(page.goto(f"http://127.0.0.1:{port}/api", timeout=5000).text(), "via origin")
                finally:
                    browser.close()
                self.assertEqual(proxy.connection_attempts, ())

            for family, ip, literal in (("ipv4", "127.0.0.1", "127.0.0.1"), ("ipv6", "::1", "[::1]")):
                with self.subTest(family=family), origin(ip) as http, origin(ip, tls=tls, parallel=True) as https:
                    with IPFamilyProxy(f"{family}_only") as proxy, fixed_dns({"web.test": ["::1", "127.0.0.1"]}):
                        browser = playwright.chromium.launch(**proxy.playwright_launch_options())
                        try:
                            page = browser.new_page()
                            self.assertEqual(page.goto(f"http://{literal}:{http}/api", timeout=5000).text(), "via origin")
                            url = f"https://web.test:{https}/"
                            with self.assertRaisesRegex(Error, "ERR_CERT_AUTHORITY_INVALID"):
                                page.goto(url, timeout=5000)
                            page.close()
                            # Accept the fixture certificate only in this test context.
                            page = browser.new_page(ignore_https_errors=True)
                            response = page.goto(url, timeout=10000)
                            self.assertEqual(response.security_details()["subjectName"], "web.test")
                            page.wait_for_function("document.querySelector('#result').textContent === 'via origin'")
                            self.assertEqual(page.locator("#result").evaluate("el => getComputedStyle(el).color"), "rgb(1, 2, 3)")
                        finally:
                            browser.close()
                        attempts = [entry for entry in proxy.connection_attempts if entry.success]
                        self.assertTrue(any(entry.port == http and entry.remote_ip == ip for entry in attempts))
                        https_attempts = [entry for entry in attempts if entry.port == https]
                        self.assertGreaterEqual(len(https_attempts), 2)
                        self.assertEqual({(entry.remote_ip, entry.upstream_family) for entry in https_attempts}, {(ip, family)})
