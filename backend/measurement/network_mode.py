import ipaddress
import json
import socket
import subprocess
from datetime import datetime, timezone
from typing import Literal


MeasurementMode = Literal["unrestricted", "ipv4_only", "ipv6_only"]


class UnsupportedNetworkModeError(RuntimeError):
    pass


def validate_mode(mode: str) -> MeasurementMode:
    if mode not in ("unrestricted", "ipv4_only", "ipv6_only"):
        raise ValueError("Measurement mode must be unrestricted, ipv4_only, or ipv6_only")
    return mode


def _windows_ipv6_routes() -> list[str]:
    if socket.gethostname() == "":
        return []

    command = (
        "Get-NetRoute -AddressFamily IPv6 "
        "| Where-Object { $_.DestinationPrefix -eq '::/0' } "
        "| Select-Object -ExpandProperty DestinationPrefix "
        "| ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, str):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, str)]
    return []


def _windows_local_ipv6_addresses() -> list[str]:
    command = (
        "Get-NetIPAddress -AddressFamily IPv6 "
        "| Where-Object { $_.AddressState -eq 'Preferred' } "
        "| Select-Object -ExpandProperty IPAddress "
        "| ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, str):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, str)]
    return []


def build_network_mode_report(mode: str) -> dict:
    normalized_mode = validate_mode(mode)
    ipv6_routes = _windows_ipv6_routes()
    ipv6_addresses = _windows_local_ipv6_addresses()

    has_global_ipv6_address = any(
        not ipaddress.ip_address(address).is_link_local
        and not ipaddress.ip_address(address).is_loopback
        for address in ipv6_addresses
    )
    has_global_ipv6_route = bool(ipv6_routes)

    if normalized_mode == "unrestricted":
        return {
            "requested_measurement_mode": "unrestricted",
            "network_enforcement_mechanism": "none",
            "enforcement_verification_status": "not_applicable",
            "verification_evidence": {
                "message": "Chromium uses its normal Windows networking behavior.",
                "ipv6_global_address_detected": has_global_ipv6_address,
                "ipv6_default_route_detected": has_global_ipv6_route,
            },
            "observed_connection_address_families": [],
            "nat64_status": "unknown",
            "preflight_checked_at": datetime.now(timezone.utc).isoformat(),
        }

    if normalized_mode == "ipv4_only":
        return {
            "requested_measurement_mode": "ipv4_only",
            "network_enforcement_mechanism": "chromium_disable_ipv6_flag",
            "enforcement_verification_status": "candidate_unverified",
            "verification_evidence": {
                "message": (
                    "Chromium is launched with --disable-ipv6, but this flag alone "
                    "is not independently verified as process-wide IPv4-only enforcement."
                ),
                "ipv6_global_address_detected": has_global_ipv6_address,
                "ipv6_default_route_detected": has_global_ipv6_route,
                "remote_peer_verification": "not_observed",
            },
            "observed_connection_address_families": [],
            "nat64_status": "not_applicable",
            "preflight_checked_at": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "requested_measurement_mode": "ipv6_only",
        "network_enforcement_mechanism": "unsupported",
        "enforcement_verification_status": "unsupported",
        "verification_evidence": {
            "message": (
                "No safe process-level IPv6-only mechanism is available through "
                "Playwright or standard Chromium launch options on this Windows environment."
            ),
            "ipv6_global_address_detected": has_global_ipv6_address,
            "ipv6_default_route_detected": has_global_ipv6_route,
            "ipv6_preferred_addresses": ipv6_addresses,
            "ipv4_fallback_possible": True,
        },
        "observed_connection_address_families": [],
        "nat64_status": "unknown",
        "preflight_checked_at": datetime.now(timezone.utc).isoformat(),
    }


def chromium_launch_args(mode: str) -> list[str]:
    normalized_mode = validate_mode(mode)
    if normalized_mode == "ipv4_only":
        return ["--disable-ipv6"]
    if normalized_mode == "ipv6_only":
        raise UnsupportedNetworkModeError(
            "IPv6-only Chromium measurement is unsupported: "
            "no independently verifiable process-level IPv6-only mechanism is available."
        )
    return []
