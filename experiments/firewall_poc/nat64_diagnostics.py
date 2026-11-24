import argparse
import ipaddress
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def run_powershell(command: str):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip() or f"exit code {result.returncode}"}
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw_output": result.stdout.strip()}


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def classify_ipv4only_aaaa(records: list[dict]) -> dict:
    addresses = []
    for record in records:
        address = record.get("IPAddress")
        if not address:
            continue
        try:
            parsed = ipaddress.IPv6Address(address)
        except ipaddress.AddressValueError:
            continue

        possible_ipv4 = []
        prefix_candidates = []
        packed = parsed.packed
        for suffix in ("192.0.0.170", "192.0.0.171"):
            suffix_bytes = ipaddress.IPv4Address(suffix).packed
            if suffix_bytes in packed:
                possible_ipv4.append(suffix)

        if len(packed) == 16:
            suffix_ipv4 = ipaddress.IPv4Address(packed[-4:])
            if str(suffix_ipv4) in ("192.0.0.170", "192.0.0.171"):
                prefix = ipaddress.IPv6Address(
                    (int(parsed) & (((1 << 96) - 1) << 32))
                )
                prefix_candidates.append(str(prefix) + "/96")

        addresses.append({
            "address": address,
            "is_well_known_64ff9b": parsed in ipaddress.IPv6Network("64:ff9b::/96"),
            "possible_embedded_ipv4only_address": possible_ipv4,
            "possible_nat64_prefix": prefix_candidates,
        })

    return {
        "addresses": addresses,
        "dns64_synthesis_evidence": (
            "possible" if addresses else "not_observed"
        ),
        "interpretation": (
            "AAAA results for ipv4only.arpa may indicate DNS64, but this is not "
            "proof of NAT64 translation or native IPv6 support."
            if addresses
            else "No AAAA result was observed; DNS64 remains unknown, not proven absent."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    ipv4_addresses = run_powershell(
        "Get-NetIPAddress -AddressFamily IPv4 "
        "| Where-Object { $_.AddressState -eq 'Preferred' } "
        "| Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState "
        "| ConvertTo-Json -Compress"
    )
    ipv6_addresses = run_powershell(
        "Get-NetIPAddress -AddressFamily IPv6 "
        "| Where-Object { $_.AddressState -eq 'Preferred' } "
        "| Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState "
        "| ConvertTo-Json -Compress"
    )
    default_routes = run_powershell(
        "Get-NetRoute -AddressFamily IPv4,IPv6 "
        "| Where-Object { $_.State -eq 'Alive' -and "
        "($_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0') } "
        "| Select-Object AddressFamily,DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,State "
        "| ConvertTo-Json -Compress"
    )
    dns_servers = run_powershell(
        "Get-DnsClientServerAddress "
        "| Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses "
        "| ConvertTo-Json -Compress"
    )
    routes = run_powershell(
        "Get-NetRoute -AddressFamily IPv6 "
        "| Where-Object { $_.State -eq 'Alive' } "
        "| Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,State "
        "| ConvertTo-Json -Compress"
    )
    ipv4only_dns = run_powershell(
        "Resolve-DnsName ipv4only.arpa -Type AAAA -ErrorAction SilentlyContinue "
        "| Select-Object Name,Type,IPAddress "
        "| ConvertTo-Json -Compress"
    )
    ipv4only_a = run_powershell(
        "Resolve-DnsName ipv4only.arpa -Type A -ErrorAction SilentlyContinue "
        "| Select-Object Name,Type,IPAddress "
        "| ConvertTo-Json -Compress"
    )
    ipv4only_aaaa_current_ipv6_resolver = run_powershell(
        "$resolver = (Get-DnsClientServerAddress -AddressFamily IPv6 "
        "| Where-Object { $_.InterfaceAlias -eq 'Wi-Fi' } "
        "| Select-Object -First 1 -ExpandProperty ServerAddresses | "
        "Select-Object -First 1); "
        "if ($resolver) { "
        "Resolve-DnsName ipv4only.arpa -Type AAAA -Server $resolver "
        "-ErrorAction SilentlyContinue "
        "| Select-Object Name,Type,IPAddress "
        "| ConvertTo-Json -Compress "
        "} else { '{\\\"resolver\\\":null}' }"
    )
    ipv4only_aaaa_current_ipv4_resolver = run_powershell(
        "$resolver = (Get-DnsClientServerAddress -AddressFamily IPv4 "
        "| Where-Object { $_.InterfaceAlias -eq 'Wi-Fi' } "
        "| Select-Object -First 1 -ExpandProperty ServerAddresses | "
        "Select-Object -First 1); "
        "if ($resolver) { "
        "Resolve-DnsName ipv4only.arpa -Type AAAA -Server $resolver "
        "-ErrorAction SilentlyContinue "
        "| Select-Object Name,Type,IPAddress "
        "| ConvertTo-Json -Compress "
        "} else { '{\\\"resolver\\\":null}' }"
    )
    nat64_prefix_routes = run_powershell(
        "Get-NetRoute -AddressFamily IPv6 "
        "| Where-Object { $_.DestinationPrefix -eq '64:ff9b::/96' } "
        "| Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,State "
        "| ConvertTo-Json -Compress"
    )
    teredo = run_powershell("netsh interface ipv6 show teredo")
    clat_indicators = run_powershell(
        "Get-NetAdapter -IncludeHidden "
        "| Where-Object { $_.Name -match 'clat|464xl|cellular|wwan' -or "
        "$_.InterfaceDescription -match 'clat|464xl|cellular|wwan' } "
        "| Select-Object Name,InterfaceDescription,Status,MacAddress "
        "| ConvertTo-Json -Compress"
    )

    dns_records = as_list(ipv4only_dns)
    dns_analysis = classify_ipv4only_aaaa([
        record for record in dns_records if isinstance(record, dict)
    ])
    report = {
        "schema_version": "1-firewall-poc-nat64",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "active_addresses": {
            "ipv4": ipv4_addresses,
            "ipv6": ipv6_addresses,
        },
        "default_routes": default_routes,
        "dns_servers": dns_servers,
        "ipv6_routes": routes,
        "ipv4only_arpa_a_records": ipv4only_a,
        "ipv4only_arpa_aaaa_records": ipv4only_dns,
        "ipv4only_arpa_aaaa_via_current_ipv6_dns": ipv4only_aaaa_current_ipv6_resolver,
        "ipv4only_arpa_aaaa_via_current_ipv4_dns": ipv4only_aaaa_current_ipv4_resolver,
        "dns64_analysis": dns_analysis,
        "well_known_nat64_prefix_route": nat64_prefix_routes,
        "teredo_status": teredo,
        "clat_464xlat_indicators": clat_indicators,
        "nat64_status": "unknown",
        "limitations": [
            "A missing 64:ff9b::/96 route does not prove NAT64 is absent.",
            "NAT64 may use a network-specific prefix.",
            "DNS64 synthesis and NAT64 translation are separate mechanisms.",
            "Available Windows diagnostics do not conclusively identify 464XLAT.",
        ],
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as output_file:
            json.dump(report, output_file, indent=2)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
