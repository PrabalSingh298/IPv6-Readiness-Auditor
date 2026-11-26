import re
from collections import Counter


_ERROR_CODE = re.compile(r"(?:net::)?(ERR_[A-Z0-9_]+|DNS_PROBE_FINISHED_[A-Z0-9_]+)(?![\w-])")
_PROXY_ERRORS = {"ERR_SOCKS_CONNECTION_FAILED", "ERR_SOCKS_CONNECTION_HOST_UNREACHABLE", "ERR_ADDRESS_UNREACHABLE"}
_TIMEOUT_STAGES = {
    "ERR_DNS_TIMED_OUT": "dns",
    "ERR_CONNECTION_TIMED_OUT": "connection",
    "ERR_TIMED_OUT": "request",
}
_TCP_ERRORS = {
    "ERR_CONNECTION_ABORTED", "ERR_CONNECTION_CLOSED", "ERR_CONNECTION_FAILED", "ERR_CONNECTION_REFUSED",
    "ERR_CONNECTION_RESET", "ERR_ADDRESS_UNREACHABLE", "ERR_NETWORK_UNREACHABLE", "ERR_SOCKET_NOT_CONNECTED",
}


def classify_resource(resource: dict, *, mode: str = "unrestricted", origin_request_count: int = 0) -> dict:
    status = resource.get("http_status")
    failure = resource.get("failure") or {}
    loading_failed = (resource.get("raw_evidence") or {}).get("cdp_loading_failed") or {}
    evidence = {"http_status": status, "browser_error": failure.get("browser_error"),
                "browser_error_text": failure.get("browser_error_text")}
    if loading_failed:
        evidence["cdp_loading_failed"] = loading_failed

    def result(category: str, reason: str, source: str, **details: str) -> dict:
        return {"category": category, "reason": reason, "evidence": {**evidence, "source": source, **details}}

    if resource.get("success") is True:
        return result("success", "The browser received a successful HTTP response.", "browser_response")
    if isinstance(status, int) and 400 <= status <= 599:
        return result("http_failure", f"The server returned HTTP {status}.", "browser_response")

    codes = {
        match[1] for text in (failure.get("browser_error"), failure.get("browser_error_text"), loading_failed.get("errorText"))
        if text and (match := _ERROR_CODE.match(text))
    }
    # Combined results for one URL can contain conflicting evidence from retries.
    if len(codes) > 1:
        return result("unknown", "Browser errors disagree for this resource URL.", "insufficient_evidence")
    code = next(iter(codes), "")
    if (loading_failed.get("blockedReason") or loading_failed.get("corsErrorStatus") or loading_failed.get("canceled")
            or code == "ERR_ABORTED" or code.startswith("ERR_BLOCKED_BY_")):
        return result("browser_failure", "The browser reported that the request was blocked or canceled.", "browser_request")
    if code in _TIMEOUT_STAGES:
        stage = _TIMEOUT_STAGES[code]
        return result("timeout", f"The browser reported a {stage} timeout.", "browser_request", timeout_stage=stage)
    if code in {"ERR_NAME_NOT_RESOLVED", "ERR_NAME_RESOLUTION_FAILED"} or code.startswith(("ERR_DNS_", "DNS_PROBE_FINISHED_")):
        return result("dns_failure", "The browser reported a hostname resolution failure.", "browser_request")
    if code.startswith(("ERR_CERT_", "ERR_SSL_")) or code in {"ERR_BAD_SSL_CLIENT_AUTH_CERT", "ERR_NO_SSL_VERSIONS_ENABLED"}:
        return result("tls_failure", "The browser reported a TLS or certificate failure.", "browser_request")

    if code in _PROXY_ERRORS and mode in {"ipv4_only", "ipv6_only"} and status is None:
        origin = (resource.get("ip_evidence") or {}).get("proxy_origin") or {}
        reasons = origin.get("failure_reasons") or []
        if origin:
            evidence["proxy_origin"] = {"hostname": origin["hostname"], "port": origin["port"],
                                        "scope": "hostname_port", "failure_reasons": reasons,
                                        "successful_attempts": origin.get("successful_attempts", 0),
                                        "observed_requests": origin_request_count}
        if len(reasons) == 1 and not origin.get("successful_attempts"):
            reason = reasons[0]
            if reason == "address_family_unavailable":
                family = "IPv6" if mode == "ipv6_only" else "IPv4"
                return result("address_family_unavailable", f"{family} address unavailable for this hostname.",
                              "proxy_origin", requested_family=family.lower())
            if reason == "dns_failure":
                return result("dns_failure", "The proxy could not resolve this hostname.", "proxy_origin")
            if reason == "dns_timeout" or (reason == "connection_timeout" and origin_request_count == 1):
                stage = "dns" if reason == "dns_timeout" else "connection"
                return result("timeout", f"The proxy reported a {stage} timeout for this endpoint.", "proxy_origin", timeout_stage=stage)
            if reason == "connection_failure" and origin_request_count == 1:
                return result("connection_failure", "The proxy reported failed TCP attempts for this endpoint.", "proxy_origin")
        return result("unknown", "The proxy failure could not be attributed to a specific cause for this request.", "insufficient_evidence")

    if code in _TCP_ERRORS and not (mode != "unrestricted" and code in _PROXY_ERRORS):
        return result("connection_failure", "The browser reported a connection or network reachability failure.", "browser_request")
    return result("unknown", "The available evidence does not establish a specific failure stage.", "insufficient_evidence")


def failure_category_counts(resources: list[dict]) -> dict[str, int]:
    return dict(Counter(resource["failure_classification"]["category"] for resource in resources if resource.get("success") is False))
