import argparse
import ipaddress
import json
from pathlib import Path


def classify(address: str) -> str:
    address_object = ipaddress.ip_address(address)
    return "ipv4" if address_object.version == 4 else "ipv6"


def verify(report: dict) -> dict:
    observations = report.get("remote_peer_observations", [])
    families = sorted({
        item.get("address_family") or classify(item["address"])
        for item in observations
        if item.get("address_family") or item.get("address")
    })
    mode = report.get("requested_mode")

    if not families:
        return {
            "status": "inconclusive",
            "observed_address_families": [],
            "reason": "No remote peer IP observations were available.",
        }

    if mode == "ipv4_only":
        status = "verified" if families == ["ipv4"] else "failed_or_mixed"
    elif mode == "ipv6_only":
        status = "verified" if families == ["ipv6"] else "failed_or_mixed"
    elif mode == "unrestricted":
        status = "baseline_observed"
    else:
        status = "inconclusive"

    return {
        "status": status,
        "observed_address_families": families,
        "reason": "Based only on independently observed remote peer IP addresses.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()

    with args.report.open("r", encoding="utf-8") as report_file:
        report = json.load(report_file)

    result = verify(report)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
