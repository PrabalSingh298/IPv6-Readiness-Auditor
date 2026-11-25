from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from threading import Thread
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.measurement.failure_classifier import classify_resource
from backend.measurement.resource_collector import collect_resources


class FailureFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = (
                "<!doctype html><title>Failure fixture</title>"
                "<script src='/ok.js'></script>"
                "<img src='/missing'>"
                "<img src='/server-error'>"
            ).encode("utf-8")
            status = 200
            content_type = "text/html"
        elif self.path == "/missing":
            body = b"not found"
            status = 404
            content_type = "text/plain"
        elif self.path == "/server-error":
            body = b"server error"
            status = 500
            content_type = "text/plain"
        else:
            body = b"window.fixtureLoaded = true;"
            status = 200
            content_type = "application/javascript"

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class FailureClassificationTests(unittest.TestCase):
    def test_browser_error_evidence_is_classified_conservatively(self):
        cases = [
            ("net::ERR_NAME_NOT_RESOLVED", "dns_failure"),
            ("net::ERR_CONNECTION_REFUSED", "connection_failure"),
            ("net::ERR_CONNECTION_RESET", "connection_failure"),
            ("net::ERR_CERT_AUTHORITY_INVALID", "tls_failure"),
            ("net::ERR_SSL_PROTOCOL_ERROR", "tls_failure"),
            ("Page.goto: Timeout 1ms exceeded", "inconclusive"),
            ("net::ERR_FAILED", "inconclusive"),
        ]

        for browser_error, expected_category in cases:
            with self.subTest(browser_error=browser_error):
                result = classify_resource({
                    "success": False,
                    "http_status": None,
                    "failure": {
                        "browser_error": browser_error,
                        "browser_error_text": browser_error,
                    },
                })
                self.assertEqual(result["category"], expected_category)
                self.assertEqual(result["evidence"]["browser_error"], browser_error)

    def test_http_statuses_and_success(self):
        cases = [
            (200, True, "success"),
            (404, False, "http_failure"),
            (500, False, "http_failure"),
        ]

        for status, success, expected_category in cases:
            with self.subTest(status=status):
                result = classify_resource({
                    "success": success,
                    "http_status": status,
                    "failure": None,
                })
                self.assertEqual(result["category"], expected_category)

    def test_collector_classifies_controlled_http_responses(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FailureFixtureHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target_url = f"http://127.0.0.1:{server.server_port}/"

        try:
            with patch(
                "backend.measurement.resource_collector.validate_url",
                side_effect=lambda url: url,
            ):
                report = collect_resources(target_url, timeout_ms=10000)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

        resources = {resource["url"]: resource for resource in report["resources"]}
        self.assertEqual(
            resources[target_url + "missing"]["failure_classification"]["category"],
            "http_failure",
        )
        self.assertEqual(
            resources[target_url + "server-error"]["failure_classification"]["category"],
            "http_failure",
        )
        self.assertEqual(
            resources[target_url + "ok.js"]["failure_classification"]["category"],
            "success",
        )
        self.assertEqual(
            resources[target_url + "missing"]["failure_classification"]["evidence"]["http_status"],
            404,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
