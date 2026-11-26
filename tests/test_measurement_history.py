import csv
import json
import socket
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import urljoin
from uuid import uuid4

import uvicorn
from playwright.sync_api import expect, sync_playwright

from backend.api import routes
from backend.main import app
from backend.measurement import resource_collector
from test_dependency_graph import FixtureRequestHandler
from test_ip_family_proxy import IPv6Server


@contextmanager
def dashboard_server():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while thread.is_alive() and not server.started and time.monotonic() < deadline:
                time.sleep(0.05)
            if not server.started:
                raise RuntimeError("Dashboard test server did not start")
            yield url
        finally:
            server.should_exit = True
            thread.join(5)


class MeasurementHistoryTests(unittest.TestCase):
    def test_saved_reports_reopen_after_restart_without_a_measurement(self):
        with (
            TemporaryDirectory() as directory,
            patch.object(resource_collector, "DATA_DIRECTORY", Path(directory)),
            patch.object(routes, "DATA_DIRECTORY", Path(directory)),
            patch.object(routes, "_jobs", {}),
            IPv6Server(("::1", 0), FixtureRequestHandler) as fixture,
            sync_playwright() as playwright,
        ):
            target = f"http://[::1]:{fixture.server_port}/index.html"
            origin = Thread(target=fixture.serve_forever, daemon=True)
            origin.start()
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page()
                with dashboard_server() as url, patch.object(
                    routes, "validate_url", side_effect=lambda value: value,
                ), patch.object(resource_collector, "validate_url", side_effect=lambda value: value):
                    page.goto(url)
                    baseline = self.measure(page, target, "unrestricted")
                    ipv6 = self.measure(page, target, "ipv6_only")
                    page.get_by_role("button", name="Measurement History", exact=True).click()
                    expect(page.locator("#history-rows tr")).to_have_count(2)
                    history = page.request.get(f"{url}/api/measurements/history").json()
                    self.assertEqual([entry["measurement_id"] for entry in history],
                                     [ipv6["measurement_id"], baseline["measurement_id"]])
                    self.assertEqual([entry["target_url"] for entry in history], [target, target])
                    self.assertIsNone(history[1]["http_ipv6_readiness_percent"])
                    self.assertEqual(history[0]["http_ipv6_readiness_percent"], 100)
                    self.assertTrue(all("resources" not in entry for entry in history))

                # Stop the measured site as well as the dashboard before opening saved reports.
                fixture.shutdown()
                origin.join(5)
                for i in range(12):
                    self.write_legacy_report(Path(directory), i)
                (Path(directory) / "phase3_invalid.json").write_text("invalid json!", encoding="utf-8")
                (Path(directory) / "phase3_binary.json").write_bytes(b"\xff")
                (Path(directory) / "phase3_incompatible.json").write_text(
                    json.dumps({"measurement_id": str(uuid4()), "target_url": target, "resources": [None]}), encoding="utf-8",
                )
                (Path(directory) / "phase3_invalid_evidence.json").write_text(
                    json.dumps({"measurement_id": str(uuid4()), "target_url": target,
                                "resources": [{"url": target, "ip_evidence": "invalid"}]}), encoding="utf-8",
                )

                with patch.object(routes, "_jobs", {}), patch.object(routes, "collect_resources") as collect, patch.object(
                    resource_collector, "sync_playwright",
                ) as measurement_browser, patch("socket.getaddrinfo", wraps=socket.getaddrinfo) as dns, dashboard_server() as url:
                    requests = []
                    page.on("request", lambda request: requests.append((request.method, request.url)))
                    page.goto(url)
                    page.get_by_role("button", name="Measurement History", exact=True).click()
                    expect(page.locator("#history-rows tr")).to_have_count(14)
                    expect(page.locator("#history-rows tr").first).to_contain_text(target)
                    scroller = page.get_by_role("region", name="Saved measurement list")
                    self.assertTrue(scroller.evaluate("node => node.scrollHeight > node.clientHeight"))
                    scroller.evaluate("node => node.scrollTop = node.scrollHeight")
                    self.assertGreater(scroller.evaluate("node => node.scrollTop"), 0)

                    page.get_by_role("searchbox", name="Search saved measurements").fill("[::1]")
                    expect(page.locator("#history-rows tr")).to_have_count(2)
                    page.get_by_label("Filter saved measurements by mode").select_option("ipv6_only")
                    expect(page.locator("#history-rows tr")).to_have_count(1)
                    page.get_by_role("button", name="View Measurement", exact=True).click()
                    expect(page.locator("#report-view-label")).to_have_text("HISTORICAL MEASUREMENT")
                    expect(page.locator("#http-readiness")).to_have_text("100%")
                    expect(page.locator("#network-peers")).to_contain_text("::1")
                    expect(page.locator("#dependency-graph path").first).to_be_visible()
                    expect(page.locator("#resource-count-label")).to_have_text(f"{len(ipv6['resources'])} of {len(ipv6['resources'])} resources")
                    historic = self.download(page, "json").json()
                    for field in ("started_at", "summary", "resources", "dependency_graph", "network_mode", "readiness"):
                        self.assertEqual(historic[field], ipv6[field], field)
                    expected_date = page.evaluate("value => new Date(value).toLocaleString()", historic["started_at"])
                    expect(page.locator("#result-subtitle")).to_contain_text(expected_date)
                    csv_row = next(csv.DictReader(self.download(page, "csv").text().splitlines()))
                    self.assertEqual(float(csv_row["http_ipv6_readiness_percent"]), 100)

                    page.get_by_role("button", name="Back to History").click()
                    expect(page.locator("#history-rows tr")).to_have_count(1)
                    page.get_by_label("Filter saved measurements by mode").select_option("unrestricted")
                    page.get_by_role("button", name="View Measurement", exact=True).click()
                    expect(page.locator("#http-readiness")).to_have_text("—")
                    self.assertEqual(self.download(page, "json").json()["measurement_id"], baseline["measurement_id"])
                    page.get_by_role("button", name="New Measurement", exact=True).click()
                    expect(page.get_by_role("button", name="Run measurement")).to_be_visible()

                    for suffix, expected in (("invalid-id", 422), (str(uuid4()), 404)):
                        self.assertEqual(page.request.get(f"{url}/api/measurements/history/{suffix}").status, expected)
                    collect.assert_not_called()
                    measurement_browser.assert_not_called()
                    self.assertFalse(any(call.args[0] in ("::1", "legacy.example") for call in dns.call_args_list))
                    self.assertTrue(requests)
                    self.assertTrue(all(method == "GET" and request_url.startswith(url + "/")
                                        for method, request_url in requests))
            finally:
                browser.close()
                fixture.shutdown()
                origin.join(5)

    def measure(self, page, target, mode):
        page.locator("#url-input").fill(target)
        page.locator("#mode-select").select_option(mode)
        page.get_by_role("button", name="Run measurement").click()
        expect(page.locator("#status-message")).to_contain_text("Measurement completed", timeout=20000)
        return self.download(page, "json").json()

    def download(self, page, format):
        href = page.locator(f"#download-{format}").get_attribute("href")
        response = page.request.get(urljoin(page.url, href))
        self.assertTrue(response.ok)
        return response

    @staticmethod
    def write_legacy_report(directory, i):
        report = {
            "measurement_id": str(uuid4()), "target_url": f"https://legacy.example/{i}",
            "started_at": f"2025-01-{i+1:02d}T00:00:00+00:00", "resources": [],
        }
        path = directory / f"phase3_legacy_{i}.json"
        path.write_text(json.dumps(report), encoding="utf-8")
