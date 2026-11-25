import json
import ipaddress
import sys
import time
import uuid
from contextlib import ExitStack, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import Error as PlaywrightError, Request, Response, sync_playwright

from backend.measurement.dependency_graph import build_dependency_graph
from backend.measurement.failure_classifier import classify_resource
from backend.measurement.ip_family_proxy import IPFamilyProxy
from backend.measurement.network_mode import build_network_mode_report, validate_mode
from backend.measurement.readiness import calculate_readiness, classify_dns_capability
from backend.measurement.resource_ip_evidence import add_ip_evidence, response_peer


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIRECTORY = PROJECT_ROOT / "data"


def validate_url(url: str) -> str:
    parsed = urlparse(url.strip())

    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed")

    hostname = parsed.hostname.lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost targets are not allowed in the Phase 2 collector")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None and (address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError("Private and loopback IP addresses are not allowed")

    return url.strip()


def _elapsed_milliseconds(start_time: float) -> float:
    return round((time.perf_counter() - start_time) * 1000, 3)


def collect_resources(
    url: str,
    timeout_ms: int = 30000,
    headless: bool = True,
    measurement_mode: str = "unrestricted",
) -> dict:
    target_url = validate_url(url)
    mode = validate_mode(measurement_mode)
    proxy = IPFamilyProxy(mode) if mode != "unrestricted" else None
    measurement_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    measurement_start = time.perf_counter()
    resources: dict[str, dict] = {}
    cdp_initiators: dict[str, list[dict]] = {}
    network_responses: list[tuple[str, str, int, str | None]] = []
    cached_requests: set[str] = set()
    navigation: dict = {
        "requested_url": target_url,
        "attempted": False,
        "completed": False,
        "timed_out": False,
        "http_status": None,
        "final_url": None,
        "document_title": None,
        "duration_ms": None,
        "error": None,
        "error_type": None,
    }

    def on_request(request: Request) -> None:
        request_url = request.url
        if request_url not in resources:
            parsed = urlparse(request_url)
            resources[request_url] = {
                "url": request_url,
                "hostname": parsed.hostname,
                "method": request.method,
                "resource_type": request.resource_type,
                "http_status": None,
                "success": None,
                "timing": {
                    "request_started_at_ms": _elapsed_milliseconds(measurement_start),
                    "response_received_at_ms": None,
                    "duration_ms": None,
                },
                "failure": None,
                "dependency": {
                    "initiator_url": None,
                    "initiator_type": None,
                    "initiator_line_number": None,
                    "initiator_column_number": None,
                    "parent_resource_url": None,
                    "depth": None,
                    "relationship_status": "unavailable",
                    "evidence": None,
                },
                "raw_evidence": {
                    "is_navigation_request": request.is_navigation_request(),
                    "frame_url": request.frame.url if request.frame else None,
                    "request_post_data": request.post_data,
                },
                "_started_perf": time.perf_counter(),
                "_response_evidence": None,
            }

    def on_response(response: Response) -> None:
        resource = resources.get(response.request.url)
        if resource is None:
            on_request(response.request)
            resource = resources[response.request.url]

        resource["http_status"] = response.status
        resource["success"] = 200 <= response.status < 400
        resource["timing"]["response_received_at_ms"] = _elapsed_milliseconds(measurement_start)
        resource["timing"]["duration_ms"] = _elapsed_milliseconds(resource["_started_perf"])
        resource["raw_evidence"]["response"] = {
            "status_text": response.status_text,
            "from_service_worker": response.from_service_worker,
            "request_headers": dict(response.request.headers),
            "response_headers": dict(response.headers),
        }

    def on_request_failed(request: Request, failure: str) -> None:
        resource = resources.get(request.url)
        if resource is None:
            on_request(request)
            resource = resources[request.url]

        resource["success"] = False
        resource["timing"]["duration_ms"] = _elapsed_milliseconds(resource["_started_perf"])
        resource["failure"] = {
            "browser_error": failure,
            "browser_error_text": request.failure,
        }

    try:
        with proxy or nullcontext(), sync_playwright() as playwright, ExitStack() as browser_lifecycle:
            launch_options = proxy.playwright_launch_options() if proxy else {}
            browser = playwright.chromium.launch(headless=headless, **launch_options)
            browser_lifecycle.callback(browser.close)
            page = browser.new_page()

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfailed", lambda request: on_request_failed(request, request.failure))

            cdp_session = page.context.new_cdp_session(page)
            cdp_session.send("Network.enable")

            def record_network_response(event: dict, response: dict) -> None:
                if not response.get("url") or any(response.get(field) for field in (
                    "fromDiskCache", "fromPrefetchCache", "fromServiceWorker",
                )):
                    return
                peer = response_peer(response) if proxy is None else None
                network_responses.append((event["requestId"], response["url"], response["status"], peer))

            def on_request_will_be_sent(event: dict) -> None:
                if redirect := event.get("redirectResponse"):
                    record_network_response(event, redirect)
                request_url = event.get("request", {}).get("url")
                if not request_url:
                    return

                initiator = event.get("initiator") or {}
                stack = initiator.get("stack") or {}
                call_frames = stack.get("callFrames") or []
                frame = call_frames[0] if call_frames else {}
                initiator_url = (
                    initiator.get("url")
                    or frame.get("url")
                    or None
                )
                initiator_record = {
                    "initiator_url": initiator_url,
                    "initiator_type": initiator.get("type"),
                    "initiator_line_number": (
                        initiator.get("lineNumber")
                        if initiator.get("lineNumber") is not None
                        else frame.get("lineNumber")
                    ),
                    "initiator_column_number": (
                        initiator.get("columnNumber")
                        if initiator.get("columnNumber") is not None
                        else frame.get("columnNumber")
                    ),
                    "evidence": "chromium_cdp_initiator",
                }
                cdp_initiators.setdefault(request_url, []).append(initiator_record)

            cdp_session.on("Network.requestWillBeSent", on_request_will_be_sent)
            cdp_session.on("Network.responseReceived", lambda event: record_network_response(event, event["response"]))
            cdp_session.on("Network.requestServedFromCache", lambda event: cached_requests.add(event["requestId"]))

            try:
                navigation["attempted"] = True
                response = page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
                navigation["completed"] = True
                navigation["final_url"] = page.url
                navigation["document_title"] = page.title()
                navigation["http_status"] = response.status if response is not None else None
            except PlaywrightError as error:
                navigation["completed"] = False
                navigation["error"] = str(error)
                navigation["error_type"] = type(error).__name__
                navigation["timed_out"] = "Timeout" in str(error) or "timeout" in str(error)
            except Exception as error:
                navigation["completed"] = False
                navigation["error"] = str(error)
                navigation["error_type"] = type(error).__name__

            page.wait_for_timeout(1000)
            navigation["duration_ms"] = _elapsed_milliseconds(measurement_start)
            page.close()
    except Exception as error:
        navigation["completed"] = False
        navigation["error"] = str(error)
        navigation["error_type"] = type(error).__name__

    cleaned_resources = []
    for resource in resources.values():
        resource.pop("_started_perf", None)
        resource.pop("_response_evidence", None)
        initiators = cdp_initiators.get(resource["url"], [])
        if initiators:
            resource["dependency"].update(initiators[0])
        resource["failure_classification"] = classify_resource(resource)
        cleaned_resources.append(resource)

    response_peers: dict[str, set[str]] = {}
    for request_id, resource_url, status, peer in network_responses:
        if request_id in cached_requests:
            continue
        if peer:
            response_peers.setdefault(resource_url, set()).add(peer)
        resource = resources.get(resource_url)
        if resource and resource["http_status"] == status:
            response = resource["raw_evidence"].get("response")
            if response and not response["from_service_worker"]:
                response["from_network"] = True
    attempts = proxy.connection_attempts if proxy else ()
    add_ip_evidence(cleaned_resources, response_peers, proxy.hostname_resolutions if proxy else {}, attempts)
    for resource in cleaned_resources:
        resource["dns_capability"] = classify_dns_capability(resource)
    dependency_graph = build_dependency_graph(cleaned_resources)

    direct_peers = {peer for peers in response_peers.values() for peer in peers}
    network_mode = build_network_mode_report(mode, attempts, direct_peers)
    network_mode["measurement_completed_at"] = datetime.now(timezone.utc).isoformat()

    report = {
        "schema_version": "2.0",
        "measurement_id": measurement_id,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "measurement_mode": measurement_mode,
        "network_mode": network_mode,
        "requested_measurement_mode": measurement_mode,
        "network_enforcement_mechanism": network_mode["network_enforcement_mechanism"],
        "enforcement_verification_status": network_mode["enforcement_verification_status"],
        "verification_evidence": network_mode["verification_evidence"],
        "observed_connection_address_families": network_mode["observed_connection_address_families"],
        "nat64_status": network_mode["nat64_status"],
        "navigation": navigation,
        "resources": cleaned_resources,
        "dependency_graph": dependency_graph,
        "summary": {
            "total_resources": len(cleaned_resources),
            "successful_or_http_success": sum(
                1 for resource in cleaned_resources if resource["success"] is True
            ),
            "failed": sum(
                1 for resource in cleaned_resources if resource["success"] is False
            ),
            "status_unknown": sum(
                1 for resource in cleaned_resources if resource["success"] is None
            ),
        },
    }
    if mode == "unrestricted":
        report["readiness"] = calculate_readiness(report)

    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    hostname = urlparse(target_url).hostname or "unknown-host"
    safe_hostname = "".join(
        character if character.isalnum() or character in "-." else "-"
        for character in hostname
    )
    output_path = DATA_DIRECTORY / (
        f"phase3_{measurement_mode}_{safe_hostname}_{timestamp}_{measurement_id[:8]}.json"
    )

    with output_path.open("w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=2)

    report["output_file"] = str(output_path)
    return report


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "Usage: python -m backend.measurement.resource_collector "
            "<website-url> [timeout-ms] [unrestricted|ipv4_only|ipv6_only]"
        )
        return 2

    url = sys.argv[1]
    timeout_ms = int(sys.argv[2]) if len(sys.argv) > 2 else 30000
    measurement_mode = sys.argv[3] if len(sys.argv) > 3 else "unrestricted"

    try:
        report = collect_resources(
            url,
            timeout_ms=timeout_ms,
            measurement_mode=measurement_mode,
        )
    except ValueError as error:
        print(error)
        return 2
    except Exception as error:
        print(f"Collector error: {type(error).__name__}: {error}")
        return 1

    print(json.dumps({
        "measurement_id": report["measurement_id"],
        "target_url": report["target_url"],
        "navigation": report["navigation"],
        "summary": report["summary"],
        "output_file": report["output_file"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
