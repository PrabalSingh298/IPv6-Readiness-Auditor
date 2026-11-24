import argparse
import ipaddress
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright


def classify_address(address: str) -> str:
    return "ipv4" if ipaddress.ip_address(address).version == 4 else "ipv6"


def normalize_server_address(server_address) -> dict:
    if server_address is None:
        return {"available": False, "ip": None, "port": None, "address_family": "unknown"}

    if isinstance(server_address, (tuple, list)) and len(server_address) >= 2:
        ip_address, port = server_address[0], server_address[1]
    elif isinstance(server_address, dict):
        ip_address = server_address.get("ipAddress") or server_address.get("ip")
        port = server_address.get("port")
    else:
        return {
            "available": False,
            "ip": None,
            "port": None,
            "address_family": "unknown",
            "error": f"Unexpected server_addr type: {type(server_address).__name__}",
        }

    if ip_address is None:
        return {"available": False, "ip": None, "port": port, "address_family": "unknown"}

    ip_address = str(ip_address).strip()
    if ip_address.startswith("[") and ip_address.endswith("]"):
        ip_address = ip_address[1:-1]

    try:
        address_family = classify_address(ip_address)
    except ValueError:
        address_family = "unknown"

    return {
        "available": True,
        "ip": ip_address,
        "port": port,
        "address_family": address_family,
    }


def compare_observations(playwright_observation: dict, cdp_observation: dict) -> dict:
    playwright_available = bool(playwright_observation and playwright_observation["available"])
    cdp_available = bool(cdp_observation and cdp_observation["available"])

    if playwright_available and cdp_available:
        same_address = playwright_observation["ip"] == cdp_observation["ip"]
        return {
            "status": "agree" if same_address else "disagree",
            "playwright": "available",
            "cdp": "available",
        }
    if playwright_available:
        return {"status": "partial", "playwright": "available", "cdp": "unavailable"}
    if cdp_available:
        return {"status": "partial", "playwright": "unavailable", "cdp": "available"}
    return {"status": "both_unavailable", "playwright": "unavailable", "cdp": "unavailable"}


def enumerate_connection_processes(remote_addresses: list[str]) -> list[dict]:
    processes = []
    seen = set()

    for remote_address in sorted(set(remote_addresses)):
        command = (
            "Get-NetTCPConnection "
            f"-RemoteAddress '{remote_address}' "
            "-State Established "
            "-ErrorAction SilentlyContinue "
            "| Select-Object OwningProcess,LocalAddress,LocalPort,"
            "RemoteAddress,RemotePort,State "
            "| ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            continue
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            continue

        connections = parsed if isinstance(parsed, list) else [parsed]
        for connection in connections:
            pid = connection.get("OwningProcess")
            if pid is None:
                continue
            process_result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_Process "
                    f"| Where-Object {{ $_.ProcessId -eq {pid} }} "
                    "| Select-Object ProcessId,ParentProcessId,Name,"
                    "ExecutablePath,CommandLine "
                    "| ConvertTo-Json -Compress",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            process = None
            if process_result.returncode == 0 and process_result.stdout.strip():
                try:
                    parsed_process = json.loads(process_result.stdout)
                    process = parsed_process
                except json.JSONDecodeError:
                    pass

            key = (pid, remote_address)
            if key not in seen:
                seen.add(key)
                processes.append({
                    "connection": connection,
                    "process": process,
                })

    return processes


def capture_chromium_process_tree() -> list[dict]:
    command = (
        "Get-CimInstance Win32_Process "
        "| Where-Object { "
        "$_.ExecutablePath -and $_.ExecutablePath -like '*ms-playwright*' "
        "-and ($_.Name -eq 'chrome.exe' -or $_.Name -eq 'chrome-headless-shell.exe') "
        "} "
        "| Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine "
        "| ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else [parsed]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="https://example.com")
    parser.add_argument("--mode", choices=["unrestricted", "ipv4_only", "ipv6_only"], required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--disable-quic", action="store_true")
    args = parser.parse_args()

    response_observations = []
    failures = []
    navigation = {}
    chromium_executable = None
    chromium_processes = []
    process_tree_during_probe = []
    cdp_by_request = {}
    cdp_remote_by_request = {}
    cdp_protocol_by_request = {}

    with tempfile.TemporaryDirectory(prefix="ipv6-auditor-poc-") as profile_directory:
        with sync_playwright() as playwright:
            chromium_executable = str(playwright.chromium.executable_path)
            launch_args = ["--disable-quic"] if args.disable_quic else []
            launch_args.append("--no-proxy-server")
            context = playwright.chromium.launch_persistent_context(
                profile_directory,
                headless=True,
                args=launch_args,
                proxy=None,
            )
            page = context.pages[0] if context.pages else context.new_page()

            cdp = context.new_cdp_session(page)
            cdp.send("Network.enable")
            cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
            cdp.send("Network.setBypassServiceWorker", {"bypass": True})

            def on_response_received(event: dict) -> None:
                request_id = event.get("requestId")
                response_payload = event.get("response", {})
                if request_id:
                    cdp_by_request[request_id] = {
                        "url": response_payload.get("url"),
                        "status": response_payload.get("status"),
                        "protocol": response_payload.get("protocol"),
                    }
                    cdp_protocol_by_request[request_id] = response_payload.get("protocol")

            def on_extra_info(event: dict) -> None:
                request_id = event.get("requestId")
                remote_address = event.get("remoteIPAddress")
                if not remote_address:
                    return
                try:
                    address_family = classify_address(remote_address)
                except ValueError:
                    return
                cdp_remote_by_request[request_id] = {
                    "available": True,
                    "ip": remote_address,
                    "address_family": address_family,
                }

            cdp.on("Network.responseReceived", on_response_received)
            cdp.on("Network.responseReceivedExtraInfo", on_extra_info)

            def on_playwright_response(response) -> None:
                playwright_server_address = {
                    "available": False,
                    "ip": None,
                    "port": None,
                    "address_family": "unknown",
                }
                server_addr_error = None
                server_addr_supported = hasattr(response, "server_addr")

                try:
                    returned_address = response.server_addr()
                    playwright_server_address = normalize_server_address(returned_address)
                except Exception as error:
                    server_addr_error = f"{type(error).__name__}: {error}"

                cdp_observation = {"available": False, "ip": None, "address_family": "unknown"}
                negotiated_protocol = None

                response_observations.append({
                    "url": response.url,
                    "http_status": response.status,
                    "playwright_server_addr": playwright_server_address,
                    "playwright_server_addr_supported": server_addr_supported,
                    "playwright_server_addr_exception": server_addr_error,
                    "cdp_remote_ip": cdp_observation,
                    "negotiated_protocol": negotiated_protocol,
                    "observation_comparison": compare_observations(
                        playwright_server_address,
                        cdp_observation,
                    ),
                })

            page.on("response", on_playwright_response)
            page.on("requestfailed", lambda request: failures.append({
                "url": request.url,
                "failure": request.failure,
            }))

            try:
                response = page.goto(args.url, wait_until="domcontentloaded", timeout=30000)
                navigation = {
                    "completed": True,
                    "http_status": response.status if response else None,
                    "final_url": page.url,
                }
            except Exception as error:
                navigation = {
                    "completed": False,
                    "http_status": None,
                    "final_url": page.url,
                    "error": str(error),
                    "error_type": type(error).__name__,
                }

            page.wait_for_timeout(1000)

            for observation in response_observations:
                cdp_observation = {"available": False, "ip": None, "address_family": "unknown"}
                negotiated_protocol = None
                for request_id, cdp_response in cdp_by_request.items():
                    if cdp_response.get("url") == observation["url"]:
                        cdp_observation = cdp_remote_by_request.get(
                            request_id,
                            cdp_observation,
                        )
                        negotiated_protocol = cdp_protocol_by_request.get(request_id)
                        break
                observation["cdp_remote_ip"] = cdp_observation
                observation["negotiated_protocol"] = negotiated_protocol
                observation["observation_comparison"] = compare_observations(
                    observation["playwright_server_addr"],
                    cdp_observation,
                )

            if os.name == "nt":
                process_tree_during_probe = capture_chromium_process_tree()
                remote_addresses = []
                for observation in response_observations:
                    playwright_address = observation["playwright_server_addr"]
                    if playwright_address.get("available"):
                        remote_addresses.append(playwright_address["ip"])
                    cdp_address = observation["cdp_remote_ip"]
                    if cdp_address.get("available"):
                        remote_addresses.append(cdp_address["ip"])
                chromium_processes = enumerate_connection_processes(remote_addresses)

            context.close()

    unique_observations = []
    seen = set()
    for observation in response_observations:
        for source_name in ("playwright_server_addr", "cdp_remote_ip"):
            source = observation[source_name]
            if not source.get("available"):
                continue
            item = {
                "address": source["ip"],
                "address_family": source["address_family"],
                "source": source_name,
            }
            key = (item["address"], item["address_family"], item["source"])
            if key not in seen:
                seen.add(key)
                unique_observations.append(item)

    report = {
        "schema_version": "1-firewall-poc",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "url": args.url,
        "requested_mode": args.mode,
        "chromium_executable": chromium_executable,
        "fresh_temporary_profile": True,
        "quic_disabled": args.disable_quic,
        "chromium_processes_during_probe": chromium_processes,
        "process_tree_during_probe": process_tree_during_probe,
        "navigation": navigation,
        "response_observations": response_observations,
        "remote_peer_observations": unique_observations,
        "failed_requests": failures,
        "unknown_observations": len(unique_observations) == 0,
    }

    network_owner_executables = sorted({
        item["process"]["ExecutablePath"]
        for item in chromium_processes
        if item.get("process") and item["process"].get("ExecutablePath")
    })
    report["network_owner_executables"] = network_owner_executables
    report["browser_executable_matches_network_owner"] = (
        bool(network_owner_executables)
        and chromium_executable in network_owner_executables
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as output_file:
            json.dump(report, output_file, indent=2)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
