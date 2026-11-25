from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.measurement.dependency_graph import build_dependency_graph
from backend.measurement.resource_collector import collect_resources


FIXTURE_DIRECTORY = PROJECT_ROOT / "controlled_site" / "dependency_test"


class FixtureRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FIXTURE_DIRECTORY), **kwargs)

    def do_GET(self):
        if self.path in ("/api/fetch", "/api/xhr"):
            body = json.dumps({"message": "fixture API response"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, format, *args):
        pass


class DependencyGraphTests(unittest.TestCase):
    def test_unknown_initiator_does_not_create_edge(self):
        resources = [
            {
                "url": "https://example.test/",
                "resource_type": "document",
                "raw_evidence": {"is_navigation_request": True},
                "dependency": {
                    "initiator_url": None,
                    "initiator_type": "other",
                    "parent_resource_url": None,
                    "depth": None,
                },
            },
            {
                "url": "https://cdn.test/app.js",
                "resource_type": "script",
                "raw_evidence": {"is_navigation_request": False},
                "dependency": {
                    "initiator_url": "https://not-captured.test/parent.js",
                    "initiator_type": "script",
                    "parent_resource_url": None,
                    "depth": None,
                },
            },
        ]

        graph = build_dependency_graph(resources)

        self.assertEqual(graph["edges"], [])
        self.assertEqual(resources[1]["dependency"]["relationship_status"], "unknown")
        self.assertIsNone(resources[1]["dependency"]["depth"])

    def test_controlled_site_resource_dependencies(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureRequestHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/index.html"

        try:
            with patch(
                "backend.measurement.resource_collector.validate_url",
                side_effect=lambda target: target,
            ):
                report = collect_resources(url, timeout_ms=10000)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

        self.assertTrue(report["navigation"]["completed"])
        resources = {resource["url"]: resource for resource in report["resources"]}
        resource_types = {resource["resource_type"] for resource in report["resources"]}
        self.assertTrue(
            {"document", "stylesheet", "script", "image", "fetch", "xhr"}
            <= resource_types
        )

        root_url = url
        style_url = f"http://127.0.0.1:{server.server_port}/style.css"
        script_url = f"http://127.0.0.1:{server.server_port}/app.js"
        background_url = f"http://127.0.0.1:{server.server_port}/background.svg"
        fetch_url = f"http://127.0.0.1:{server.server_port}/api/fetch"
        xhr_url = f"http://127.0.0.1:{server.server_port}/api/xhr"

        self.assertEqual(resources[root_url]["dependency"]["depth"], 0)
        self.assertEqual(
            resources[style_url]["dependency"]["parent_resource_url"], root_url
        )
        self.assertEqual(resources[style_url]["dependency"]["initiator_type"], "parser")
        self.assertEqual(
            resources[script_url]["dependency"]["parent_resource_url"], root_url
        )
        self.assertEqual(resources[script_url]["dependency"]["initiator_type"], "parser")
        self.assertEqual(
            resources[background_url]["dependency"]["parent_resource_url"], style_url
        )
        self.assertEqual(
            resources[background_url]["dependency"]["initiator_url"], style_url
        )
        self.assertEqual(
            resources[fetch_url]["dependency"]["parent_resource_url"], script_url
        )
        self.assertEqual(resources[fetch_url]["dependency"]["initiator_type"], "script")
        self.assertEqual(
            resources[xhr_url]["dependency"]["parent_resource_url"], script_url
        )
        self.assertEqual(resources[xhr_url]["dependency"]["initiator_type"], "script")
        self.assertEqual(resources[fetch_url]["dependency"]["depth"], 2)
        self.assertEqual(resources[xhr_url]["dependency"]["depth"], 2)
        self.assertTrue(report["dependency_graph"]["edges"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
