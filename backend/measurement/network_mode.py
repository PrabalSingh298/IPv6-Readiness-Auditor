import ipaddress
from dataclasses import asdict
from typing import Literal, cast

from backend.measurement.ip_family_proxy import ConnectionAttempt


MeasurementMode = Literal["unrestricted", "ipv4_only", "ipv6_only"]


def validate_mode(mode: str) -> MeasurementMode:
    if mode not in ("unrestricted", "ipv4_only", "ipv6_only"):
        raise ValueError("Measurement mode must be unrestricted, ipv4_only, or ipv6_only")
    return cast(MeasurementMode, mode)


def build_network_mode_report(
    mode: MeasurementMode,
    attempts: tuple[ConnectionAttempt, ...] = (),
    direct_peers: set[str] | None = None,
) -> dict:
    restricted = mode != "unrestricted"
    if restricted:
        peers = {
            (attempt.remote_ip, attempt.upstream_family)
            for attempt in attempts
            if attempt.success and attempt.remote_ip and attempt.upstream_family
        }
    else:
        peers = {
            (address, f"ipv{ipaddress.ip_address(address).version}")
            for address in (direct_peers or ())
        }
    families = sorted({family for _, family in peers})

    status = "not_applicable"
    if restricted:
        if not families:
            status = "no_upstream_connections_observed"
        elif families == [mode.removesuffix("_only")]:
            status = f"verified_{mode}"
        else:
            status = "failed_or_mixed_address_families"

    return {
        "requested_measurement_mode": mode,
        "network_enforcement_mechanism": "socks5_ip_family_proxy" if restricted else "none",
        "enforcement_verification_status": status,
        "verification_evidence": {
            "message": (
                "Restricted to the selected upstream socket family for proxied Chromium TCP web traffic."
                if restricted else "Chromium uses its normal networking."
            ),
            "remote_peer_verification": (
                ("proxy_upstream_socket" if restricted else "chromium_cdp_response")
                if peers else "not_observed"
            ),
        },
        "observed_connection_address_families": families,
        "observed_remote_addresses": [{"ip": ip, "family": family} for ip, family in sorted(peers)],
        "connection_attempts": [asdict(attempt) for attempt in attempts],
        "nat64_status": "not_applicable" if mode == "ipv4_only" else "unknown",
    }
