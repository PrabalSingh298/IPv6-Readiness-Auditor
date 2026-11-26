import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import urlsplit

from backend.measurement.ip_family_proxy import ConnectionAttempt, HostnameResolution


def response_peer(response: dict) -> str | None:
    if not response.get("remoteIPAddress") or any(response.get(field) for field in (
        "fromDiskCache", "fromPrefetchCache", "fromServiceWorker",
    )):
        return None
    try:
        address = ipaddress.ip_address(response["remoteIPAddress"].strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _lookup(hostname: str) -> HostnameResolution:
    try:
        answers = socket.getaddrinfo(hostname, 0, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as error:
        return HostnameResolution(failure_reason="dns_failure", detail=str(error))
    return HostnameResolution(tuple((family, address) for family, _, _, _, address in answers))


def _resolve_missing(hostnames: set[str]) -> dict[str, HostnameResolution]:
    if not hostnames:
        return {}
    executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="resource-dns")
    try:
        pending = {host: executor.submit(_lookup, host) for host in sorted(hostnames)}
        completed, _ = wait(pending.values(), timeout=5)
        return {
            host: future.result() if future in completed else HostnameResolution(failure_reason="dns_timeout")
            for host, future in pending.items()
        }
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _address_lists(addresses: list[str]) -> dict[str, list[str]]:
    families = {"ipv4": set(), "ipv6": set()}
    for address in map(ipaddress.ip_address, addresses):
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            continue
        families[f"ipv{address.version}"].add(str(address))
    return {family: sorted(values) for family, values in families.items()}


def web_origin(url: str) -> tuple[str, int] | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass  # Chromium already serializes internationalized HTTP hostnames as ASCII.
    return host, parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)


def add_ip_evidence(
    resources: list[dict],
    response_peers: dict[str, set[str]],
    proxy_resolutions: dict[str, HostnameResolution],
    attempts: tuple[ConnectionAttempt, ...],
) -> None:
    origins = {}
    literals = {}
    for resource in resources:
        url = resource["url"]
        origin = web_origin(url)
        if origin is None:
            continue
        host, _ = origin
        try:
            ipaddress.ip_address(host)
            literals[host] = host
        except ValueError:
            pass
        origins[url] = origin

    hosts = {host for host, _ in origins.values()}
    other_resolutions = _resolve_missing(hosts - proxy_resolutions.keys() - literals.keys())
    resolved = {}
    for host in hosts:
        if host in literals:
            resolved[host] = {**_address_lists([host]), "source": "ip_literal", "scope": "hostname"}
        else:
            resolution = proxy_resolutions.get(host) or other_resolutions[host]
            addresses = [address[0] for _, address in resolution.addresses]
            resolved[host] = {
                **_address_lists(addresses),
                "source": "proxy_getaddrinfo" if host in proxy_resolutions else "system_getaddrinfo",
                "scope": "hostname",
                "failure_reason": resolution.failure_reason,
            }

    proxy_origins = {}
    for attempt in attempts:
        origin = (attempt.hostname.lower(), attempt.port)
        group = proxy_origins.setdefault(origin, {"attempted": set(), "connected": set(), "failures": set(), "successful_attempts": 0})
        if attempt.attempted_ip:
            group["attempted"].add(attempt.attempted_ip)
        if attempt.success:
            group["successful_attempts"] += 1
            if attempt.remote_ip and attempt.upstream_family:
                group["connected"].add((attempt.remote_ip, attempt.upstream_family))
        else:
            group["failures"].add(attempt.failure_reason or "unknown")

    for resource in resources:
        url = resource["url"]
        if url not in origins:
            continue
        host, port = origins[url]
        peers = [
            {"ip": ip, "family": f"ipv{ipaddress.ip_address(ip).version}",
             "source": "chromium_cdp_response", "scope": "resource_response"}
            for ip in sorted(response_peers.get(url, ()))
        ]
        evidence = {
            "resolved_addresses": resolved[host],
            "connected_peer": peers[0] if len(peers) == 1 else None,
            "response_peers": peers,
        }
        if group := proxy_origins.get((host, port)):
            evidence["proxy_origin"] = {
                "hostname": host,
                "port": port,
                "source": "proxy_upstream_socket",
                "scope": "hostname_port",
                "attempted_addresses": sorted(group["attempted"]),
                "connected_peers": [{"ip": ip, "family": family} for ip, family in sorted(group["connected"])],
                "failure_reasons": sorted(group["failures"]),
                "successful_attempts": group["successful_attempts"],
            }
        resource["ip_evidence"] = evidence
