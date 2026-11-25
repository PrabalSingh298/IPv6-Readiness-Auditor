import re


_DNS_ERROR = re.compile(
    r"ERR_NAME_NOT_RESOLVED|ERR_NAME_RESOLUTION_FAILED|ERR_DNS_[A-Z0-9_]*|"
    r"DNS_PROBE_FINISHED_[A-Z0-9_]+",
    re.IGNORECASE,
)
_TLS_ERROR = re.compile(
    r"ERR_CERT_[A-Z0-9_]+|ERR_SSL_[A-Z0-9_]+|SSL_ERROR_[A-Z0-9_]+|"
    r"TLS handshake|SSL handshake|certificate",
    re.IGNORECASE,
)
_CONNECTION_ERROR = re.compile(
    r"ERR_CONNECTION_(?:ABORTED|CLOSED|FAILED|REFUSED|RESET|TIMED_OUT)|"
    r"ERR_ADDRESS_UNREACHABLE|ERR_NETWORK_UNREACHABLE|"
    r"ERR_SOCKET_NOT_CONNECTED|ERR_TIMED_OUT",
    re.IGNORECASE,
)


def classify_resource(resource: dict) -> dict:
    status = resource.get("http_status")
    failure = resource.get("failure") or {}
    browser_error = failure.get("browser_error")
    browser_error_text = failure.get("browser_error_text")

    evidence = {
        "http_status": status,
        "browser_error": browser_error,
        "browser_error_text": browser_error_text,
    }

    if resource.get("success") is True:
        return {
            "category": "success",
            "reason": "The browser received a successful HTTP response.",
            "evidence": evidence,
        }

    if isinstance(status, int) and 400 <= status <= 599:
        return {
            "category": "http_failure",
            "reason": f"The server returned HTTP {status}.",
            "evidence": evidence,
        }

    error_text = " ".join(
        str(value) for value in (browser_error, browser_error_text) if value
    )
    if _DNS_ERROR.search(error_text):
        return {
            "category": "dns_failure",
            "reason": "The browser reported a hostname resolution failure.",
            "evidence": evidence,
        }
    if _TLS_ERROR.search(error_text):
        return {
            "category": "tls_failure",
            "reason": "The browser reported identifiable TLS or certificate failure evidence.",
            "evidence": evidence,
        }
    if _CONNECTION_ERROR.search(error_text):
        return {
            "category": "connection_failure",
            "reason": "The browser reported an identifiable connection or network timeout error.",
            "evidence": evidence,
        }

    return {
        "category": "inconclusive",
        "reason": (
            "The available evidence does not establish a specific failure stage."
        ),
        "evidence": evidence,
    }
