from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.measurement.resource_collector import collect_resources


def print_report(label: str, report: dict) -> None:
    print(f"\n{label}")
    print(f"Target: {report['target_url']}")
    print(f"Navigation completed: {report['navigation']['completed']}")
    print(f"Navigation timed out: {report['navigation']['timed_out']}")
    print(f"HTTP status: {report['navigation']['http_status']}")
    print(f"Resources observed: {report['summary']['total_resources']}")
    print(f"Successful/HTTP success: {report['summary']['successful_or_http_success']}")
    print(f"Failed browser requests: {report['summary']['failed']}")
    print(f"Status unknown: {report['summary']['status_unknown']}")
    print(f"JSON: {report['output_file']}")

    types = sorted({
        resource["resource_type"]
        for resource in report["resources"]
        if resource["resource_type"]
    })
    print("Resource types: " + (", ".join(types) if types else "none observed"))


def main() -> int:
    tests = [
        ("Example website", "https://example.com", 30000),
        ("Multi-resource website", "https://www.mozilla.org/en-US/", 30000),
    ]

    all_passed = True
    for label, url, timeout_ms in tests:
        try:
            report = collect_resources(url, timeout_ms=timeout_ms)
            print_report(label, report)
            if report["summary"]["total_resources"] < 1:
                print("FAILED: no browser resources were captured")
                all_passed = False
        except Exception as error:
            print(f"\n{label}")
            print(f"FAILED without crashing: {type(error).__name__}: {error}")
            all_passed = False

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
