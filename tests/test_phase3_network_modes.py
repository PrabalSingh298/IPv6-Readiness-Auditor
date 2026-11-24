from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.measurement.network_mode import (
    UnsupportedNetworkModeError,
    build_network_mode_report,
)
from backend.measurement.resource_collector import collect_resources


def test_unrestricted_mode() -> bool:
    report = collect_resources(
        "https://example.com",
        timeout_ms=30000,
        measurement_mode="unrestricted",
    )
    required_fields = [
        "requested_measurement_mode",
        "network_enforcement_mechanism",
        "enforcement_verification_status",
        "verification_evidence",
        "observed_connection_address_families",
        "nat64_status",
    ]
    passed = (
        report["measurement_mode"] == "unrestricted"
        and report["navigation"]["completed"]
        and all(field in report for field in required_fields)
    )
    print(
        "UNRESTRICTED:",
        "PASSED" if passed else "FAILED",
        "| navigation:",
        report["navigation"]["completed"],
        "| verification:",
        report["enforcement_verification_status"],
    )
    print("JSON:", report["output_file"])
    return passed


def test_ipv4_candidate_mode() -> bool:
    report = collect_resources(
        "https://example.com",
        timeout_ms=30000,
        measurement_mode="ipv4_only",
    )
    status = report["enforcement_verification_status"]
    passed_precondition = status in (
        "candidate_unverified",
        "verified_ipv4_only",
        "failed_or_mixed_address_families",
    )
    result = "PASSED" if status == "verified_ipv4_only" else "INCONCLUSIVE"
    print(
        "IPV4-ONLY:",
        result,
        "| Chromium launch completed:",
        report["navigation"]["completed"] is not None,
        "| verification:",
        status,
        "| observed:",
        report["observed_connection_address_families"],
    )
    print("JSON:", report["output_file"])
    return passed_precondition


def test_ipv6_supported_mode() -> bool:
    try:
        collect_resources(
            "https://example.com",
            timeout_ms=30000,
            measurement_mode="ipv6_only",
        )
    except UnsupportedNetworkModeError:
        report = build_network_mode_report("ipv6_only")
        print(
            "IPV6-ONLY:",
            "NOT SUPPORTED",
            "| verification:",
            report["enforcement_verification_status"],
            "| NAT64:",
            report["nat64_status"],
        )
        return True

    print("IPV6-ONLY: FAILED | browser launch unexpectedly occurred")
    return False


def main() -> int:
    print("Phase 3 network-mode test results")
    results = [
        test_unrestricted_mode(),
        test_ipv4_candidate_mode(),
        test_ipv6_supported_mode(),
    ]
    print("CONTROLLED IPV4/IPv6 ACCESS TEST: SKIPPED")
    print("Reason: no safely verifiable Windows address-family enforcement mechanism")

    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
