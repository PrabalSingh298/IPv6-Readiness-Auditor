from urllib.parse import urlsplit, urlunsplit


CAPABILITIES = ("ipv4_only", "dual_stack", "ipv6_only", "unknown")


def classify_dns_capability(resource: dict) -> str:
    resolved = (resource.get("ip_evidence") or {}).get("resolved_addresses") or {}
    if resolved.get("failure_reason"):
        return "unknown"
    ipv4, ipv6 = bool(resolved.get("ipv4")), bool(resolved.get("ipv6"))
    if ipv4 and ipv6:
        return "dual_stack"
    if ipv4 or ipv6:
        return "ipv4_only" if ipv4 else "ipv6_only"
    return "unknown"


def network_url_key(url: str) -> str | None:
    """Match network URLs while preserving path, query and nondefault ports."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        port = parts.port
        host = parts.hostname.encode("idna").decode("ascii") if not parts.hostname.isascii() else parts.hostname
    except (ValueError, UnicodeError):
        return None
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        host = f"{host}:{port}"
    if "@" in parts.netloc:
        host = f"{parts.netloc.rsplit('@', 1)[0]}@{host}"
    # Preserve an explicit empty query as well as query ordering and duplicates.
    key = urlunsplit((parts.scheme, host, parts.path or "/", parts.query, ""))
    return key + "?" if not parts.query and "?" in url.split("#", 1)[0] else key


def is_ipv6_comparison(report: dict) -> bool:
    return (
        report.get("measurement_mode") == "ipv6_only"
        and report.get("network_enforcement_mechanism") == "socks5_ip_family_proxy"
        and (report.get("navigation") or {}).get("attempted") is True
    )


def _network_resources(report: dict) -> dict[str, list[dict]]:
    by_url: dict[str, list[dict]] = {}
    for resource in report.get("resources", []):
        if key := network_url_key(resource.get("url") or ""):
            by_url.setdefault(key, []).append(resource)
    return by_url


def _retrieved_over_ipv6(resource: dict) -> bool:
    response = (resource.get("raw_evidence") or {}).get("response") or {}
    origin = (resource.get("ip_evidence") or {}).get("proxy_origin") or {}
    return (
        resource.get("success") is True
        and resource.get("http_status") != 304
        and response.get("from_network") is True
        and {peer.get("family") for peer in origin.get("connected_peers", [])} == {"ipv6"}
    )


def calculate_readiness(baseline: dict, ipv6_report: dict | None = None) -> dict:
    baseline_resources = _network_resources(baseline)
    counts = dict.fromkeys(CAPABILITIES, 0)
    for resources in baseline_resources.values():
        observed = {classify_dns_capability(resource) for resource in resources} - {"unknown"}
        capability = observed.pop() if len(observed) == 1 else "unknown"
        counts[capability] += 1

    total = len(baseline_resources)
    outcomes = None
    outcome_counts = None
    if ipv6_report is not None and is_ipv6_comparison(ipv6_report):
        observed = _network_resources(ipv6_report)
        outcomes = {}
        outcome_counts = dict.fromkeys(("retrieved", "failed", "undiscovered", "unverified"), 0)
        for url in baseline_resources:
            matches = observed.get(url, [])
            if not matches:
                outcome = "undiscovered"
            elif any(_retrieved_over_ipv6(resource) for resource in matches):
                outcome = "retrieved"
            elif all(resource.get("success") is False for resource in matches):
                outcome = "failed"
            else:
                outcome = "unverified"
            outcomes[url] = outcome
            outcome_counts[outcome] += 1

    return {
        "baseline_measurement_id": baseline.get("measurement_id"),
        "ipv6_measurement_id": ipv6_report.get("measurement_id") if outcomes is not None else None,
        "total_baseline_resources": total,
        "dns_counts": counts,
        "dns_ipv6_readiness_percent": round(100 * (counts["dual_stack"] + counts["ipv6_only"]) / total, 2) if total else None,
        "http_ipv6_readiness_percent": round(100 * outcome_counts["retrieved"] / total, 2) if total and outcome_counts is not None else None,
        "http_outcome_counts": outcome_counts,
        "http_resource_outcomes": outcomes,
    }
