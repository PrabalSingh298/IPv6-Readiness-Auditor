import csv
from contextlib import ExitStack
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest
from unittest.mock import patch
from urllib.parse import urljoin

import uvicorn
from playwright.sync_api import expect, sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.api import routes
from backend.main import app
from backend.measurement import resource_collector
from backend.measurement.ip_family_proxy import IPFamilyProxy
from test_dependency_graph import FIXTURE_DIRECTORY, FixtureRequestHandler
from test_ip_family_proxy import IPv6Server, fixed_dns


class Phase3Fixture(FixtureRequestHandler):
    def do_GET(self):
        if self.path != "/phase3.html":
            return super().do_GET()

        # Reuse the existing site and point two additional images at single-family listeners.
        port = self.server.server_port
        images = (
            f'<img src="http://127.0.0.1:{port}/logo.svg?ipv4" alt="IPv4 image">'
            f'<img src="http://[::1]:{port}/logo.svg?ipv6" alt="IPv6 image">'
            '<img src="http://unresolved.invalid/logo.svg" alt="Unresolved image">'
        )
        body = (FIXTURE_DIRECTORY / "index.html").read_text(encoding="utf-8")
        document = body.replace("</body>", images + "</body>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(document)))
        self.end_headers()
        self.wfile.write(document)


class Phase3Tests(unittest.TestCase):
    def test_dashboard_and_controlled_site_in_all_modes(self):
        with ExitStack() as cleanup:
            directory = Path(cleanup.enter_context(TemporaryDirectory()))
            cleanup.enter_context(patch.object(resource_collector, "DATA_DIRECTORY", directory))
            cleanup.enter_context(patch.object(routes, "DATA_DIRECTORY", directory))
            cleanup.enter_context(patch.object(routes, "_jobs", {}))
            proxies = []

            def track_proxy(mode):
                proxy = IPFamilyProxy(mode)
                proxies.append(proxy)
                return proxy

            cleanup.enter_context(patch.object(resource_collector, "IPFamilyProxy", side_effect=track_proxy))

            ipv4 = cleanup.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Phase3Fixture))
            port = ipv4.server_port
            ipv6 = cleanup.enter_context(IPv6Server(("::1", port), Phase3Fixture))
            for origin in (ipv4, ipv6):
                thread = Thread(target=origin.serve_forever, daemon=True)
                thread.start()
                cleanup.callback(thread.join, 5)
                cleanup.callback(origin.shutdown)

            listener = cleanup.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            dashboard_url = f"http://127.0.0.1:{listener.getsockname()[1]}"
            server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
            thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
            thread.start()
            cleanup.callback(thread.join, 5)
            cleanup.callback(setattr, server, "should_exit", True)
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(server.started)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                with ExitStack() as browser_cleanup:
                    browser_cleanup.callback(browser.close)
                    self.check_dashboard(browser.new_page(), dashboard_url, port, proxies)

    def check_dashboard(self, page, dashboard_url, port, proxies):
        page.goto(dashboard_url)
        target = f"http://localhost:{port}/phase3.html"
        rejected = page.request.post(f"{dashboard_url}/api/measurements", data={"url": target})
        self.assertEqual(rejected.status, 422)
        capabilities = page.request.get(f"{dashboard_url}/api/capabilities").json()["modes"]
        self.assertEqual({item["id"] for item in capabilities if item["available"]},
                         {"unrestricted", "ipv4_only", "ipv6_only"})

        with (
            patch.object(resource_collector, "validate_url", side_effect=lambda url: url),
            patch.object(routes, "validate_url", side_effect=lambda url: url),
            fixed_dns({"localhost": ["127.0.0.1", "::1"], "unresolved.invalid": None}) as resolver,
        ):
            for mode, label, family in (
                ("unrestricted", "Unrestricted", None),
                ("ipv4_only", "IPv4-only", "ipv4"),
                ("ipv6_only", "IPv6-only", "ipv6"),
            ):
                with self.subTest(mode=mode):
                    resolver.reset_mock()
                    report = self.run_dashboard_measurement(page, dashboard_url, target, mode)
                    self.assertEqual(sum(call.args[0] == "localhost" for call in resolver.call_args_list), 1)
                    expect(page.locator("#result-subtitle")).to_contain_text(label)
                    self.assertEqual(report["measurement_mode"], mode)
                    self.assertTrue(report["navigation"]["completed"])
                    self.assertTrue(report["dependency_graph"]["edges"])
                    assets = {item["url"].split("?")[-1]: item for item in report["resources"]
                              if "/logo.svg?" in item["url"]}
                    self.assertEqual(set(assets), {"ipv4", "ipv6"})
                    for asset_family, resource in assets.items():
                        self.assertEqual(resource["success"], family in (None, asset_family))
                        if not resource["success"]:
                            classification = resource["failure_classification"]
                            self.assertEqual(classification["category"], "address_family_unavailable")
                            self.assertEqual(classification["evidence"]["requested_family"], family)
                            self.assertEqual(classification["evidence"]["source"], "proxy_origin")
                    download = page.request.get(urljoin(
                        dashboard_url, page.locator("#download-csv").get_attribute("href"),
                    ))
                    self.assertTrue(download.ok)
                    self.check_ip_evidence(page, report, target, family, assets, download.text())
                    self.check_readiness(page, report, target, mode, download.text())

                    network = report["network_mode"]
                    if family is None:
                        self.assertEqual(proxies, [])
                        self.assertEqual(network["connection_attempts"], [])
                        self.assertEqual(set(network["observed_connection_address_families"]), {"ipv4", "ipv6"})
                        self.check_resource_scrolling(page)
                        continue
                    self.assertEqual(report["enforcement_verification_status"], f"verified_{mode}")
                    self.assertEqual(network["observed_remote_addresses"],
                                     [{"ip": "127.0.0.1" if family == "ipv4" else "::1", "family": family}])
                    self.assertIn("address_family_unavailable",
                                  {item["failure_reason"] for item in network["connection_attempts"]})
                    expect(page.locator("#network-peers")).to_contain_text(f"({family.replace('ipv', 'IPv')})")
                    page.locator("#connection-evidence summary").click()
                    expect(page.locator("#connection-attempts")).to_be_visible()
                    expect(page.locator("#connection-attempts")).to_contain_text("Requested IP family unavailable")
                    self.assertFalse(proxies[-1].is_running)
                    self.assertEqual(report["summary"]["failure_categories"]["address_family_unavailable"], 1)
                    expect(page.locator("#count-family")).to_have_text("1")
                    page.locator("#result-filter").select_option("address_family_unavailable")
                    family_label = family.replace("ipv", "IPv")
                    expect(page.locator("#resource-table-body tr")).to_have_count(1)
                    expect(page.locator("#resource-table-body")).to_contain_text(f"{family_label} address unavailable")
                    page.locator("#result-filter").select_option("all")
                    export = next(row for row in csv.DictReader(download.text().splitlines())
                                  if row["failure_category"] == "address_family_unavailable")
                    self.assertEqual(export["failure_requested_family"], family)
                    self.assertTrue(export["browser_error"])

            report = self.run_dashboard_measurement(
                page, dashboard_url, f"http://127.0.0.1:{port}/index.html", "ipv6_only",
            )
            self.assertFalse(report["navigation"]["completed"])
            self.assertEqual(report["enforcement_verification_status"], "no_upstream_connections_observed")
            self.assertEqual(report["network_mode"]["observed_remote_addresses"], [])
            self.assertFalse(proxies[-1].is_running)

    def check_resource_scrolling(self, page):
        page.evaluate("""() => {
            const first = activeReport.resources[0];
            const copies = Array.from({length: 45}, (_, index) => ({...first, url: `https://scroll.test/asset-${index}`}));
            activeReport.resources.push(...copies);
            renderResourceTable();
        }""")
        try:
            container = page.get_by_role("region", name="Observed resource list")
            self.assertTrue(container.evaluate("node => node.scrollHeight > node.clientHeight"))
            page.evaluate("window.scrollTo(0, 0)")
            container.evaluate("node => node.scrollTop = node.scrollHeight")
            self.assertGreater(container.evaluate("node => node.scrollTop"), 0)
            self.assertEqual(page.evaluate("window.scrollY"), 0)
            self.assertTrue(container.evaluate("node => Math.abs(node.querySelector('th').getBoundingClientRect().top - node.getBoundingClientRect().top) < 2"))
            self.assertTrue(container.evaluate("node => node.querySelector('tbody tr:last-child').getBoundingClientRect().bottom <= node.getBoundingClientRect().bottom + 1"))
            container.evaluate("node => node.scrollTop = 0")
            page.get_by_role("heading", name="Dependency graph").scroll_into_view_if_needed()
            self.assertGreater(page.evaluate("window.scrollY"), 0)
            self.assertEqual(container.evaluate("node => node.scrollTop"), 0)
            page.locator("#resource-search").fill("scroll.test/asset-44")
            expect(page.locator("#resource-table-body tr")).to_have_count(1)
            page.locator("#result-filter").select_option("failed")
            expect(page.locator("#table-empty-state")).to_be_visible()
        finally:
            page.evaluate("activeReport.resources.splice(-45)")
            page.locator("#resource-search").fill("")
            page.locator("#result-filter").select_option("all")

    def check_ip_evidence(self, page, report, target, family, assets, csv_contents):
        index, resource = next((index, item) for index, item in enumerate(report["resources"]) if item["url"] == target)
        evidence = resource["ip_evidence"]
        resolved = evidence["resolved_addresses"]
        self.assertEqual(resolved["ipv4"], ["127.0.0.1"])
        self.assertEqual(resolved["ipv6"], ["::1"])
        self.assertEqual(resolved["source"], "proxy_getaddrinfo" if family else "system_getaddrinfo")
        node = next(item for item in report["dependency_graph"]["nodes"] if item["url"] == target)
        self.assertEqual(node["ip_evidence"], evidence)
        csv_row = next(item for item in csv.DictReader(csv_contents.splitlines()) if item["url"] == target)
        self.assertEqual(csv_row["available_ipv6"], "::1")
        if family:
            self.assertIsNone(evidence["connected_peer"])
            origin = evidence["proxy_origin"]
            self.assertEqual(origin["scope"], "hostname_port")
            expected_ip = "127.0.0.1" if family == "ipv4" else "::1"
            self.assertEqual(origin["connected_peers"], [{"ip": expected_ip, "family": family}])
            self.assertEqual(origin["attempted_addresses"], [expected_ip])
            self.assertEqual(csv_row["remote_ip"], "")
            self.assertEqual(csv_row["proxy_evidence_scope"], "hostname_port")
            opposite = assets["ipv6" if family == "ipv4" else "ipv4"]["ip_evidence"]
            self.assertEqual(opposite["proxy_origin"]["connected_peers"], [])
        else:
            self.assertEqual(evidence["connected_peer"]["scope"], "resource_response")
            self.assertEqual(csv_row["remote_ip"], evidence["connected_peer"]["ip"])
            self.assertEqual(assets["ipv6"]["ip_evidence"]["connected_peer"]["ip"], "::1")

        row = page.locator(f'tr[data-resource-index="{index}"]')
        row.get_by_text("IP details", exact=True).click()
        expect(row.locator(".ip-details")).to_contain_text("Available IPv6")
        page.get_by_role("button", name=f"IP details for {target}", exact=True).press("Enter")
        expect(page.locator("#graph-node-details")).to_be_visible()
        expect(page.locator("#graph-node-details")).to_contain_text(
            "Connected peers for host and port" if family else "Chromium response",
        )

    def check_readiness(self, page, report, target, mode, csv_contents):
        readiness = report["readiness"]
        counts = readiness["dns_counts"]
        self.assertEqual((counts["ipv4_only"], counts["ipv6_only"], counts["unknown"]), (1, 1, 1))
        total = readiness["total_baseline_resources"]
        self.assertEqual(total, sum(counts.values()))
        expected_dns = round(100 * (total - 2) / total, 2)
        self.assertEqual(readiness["dns_ipv6_readiness_percent"], expected_dns)
        expect(page.locator("#dns-readiness")).to_have_text(f"{expected_dns:g}%")
        self.assertEqual(page.locator("#readiness-distribution span").count(), 4)
        expect(page.locator("#graph-capability-legend")).to_contain_text("Dual-stack")

        resources = {item["url"]: item for item in report["resources"]}
        for capability, url in (
            ("ipv4_only", next(url for url in resources if url.endswith("?ipv4"))),
            ("dual_stack", target),
            ("ipv6_only", next(url for url in resources if url.endswith("?ipv6"))),
            ("unknown", "http://unresolved.invalid/logo.svg"),
        ):
            self.assertEqual(resources[url]["dns_capability"], capability)
            node = page.get_by_role("button", name=f"IP details for {url}", exact=True)
            expect(node.locator("rect")).to_have_class(f"graph-node cap-{capability}" + (" root" if url == target else ""))
            self.assertNotEqual(node.locator("rect").evaluate("node => getComputedStyle(node).fill"), "rgb(0, 0, 0)")

        first = next(csv.DictReader(csv_contents.splitlines()))
        self.assertEqual(float(first["dns_ipv6_readiness_percent"]), expected_dns)
        if mode == "ipv6_only":
            http = readiness["http_resource_outcomes"]
            self.assertEqual(http[target], "retrieved")
            self.assertEqual(next(value for url, value in http.items() if url.endswith("?ipv4")), "failed")
            self.assertEqual(readiness["http_ipv6_readiness_percent"], round(100 * (total - 2) / total, 2))
            self.assertEqual(float(first["http_ipv6_readiness_percent"]), readiness["http_ipv6_readiness_percent"])
        else:
            self.assertIsNone(readiness["http_ipv6_readiness_percent"])
            self.assertEqual(first["http_ipv6_readiness_percent"], "")
            expect(page.locator("#http-readiness")).to_have_text("—")

    def run_dashboard_measurement(self, page, dashboard_url, target, mode):
        page.locator("#url-input").fill(target)
        page.locator("#mode-select").select_option(mode)
        page.locator("#run-button").click()
        expect(page.locator("#status-message")).to_contain_text("Measurement completed", timeout=20000)
        href = page.locator("#download-json").get_attribute("href")
        response = page.request.get(urljoin(dashboard_url, href))
        self.assertTrue(response.ok)
        return response.json()

    def test_browser_error_closes_browser_before_proxy(self):
        proxy = IPFamilyProxy("ipv4_only")

        def check_running():
            self.assertTrue(proxy.is_running)

        with (
            TemporaryDirectory() as directory,
            patch.object(resource_collector, "DATA_DIRECTORY", Path(directory)),
            patch.object(resource_collector, "IPFamilyProxy", return_value=proxy),
            patch.object(resource_collector, "sync_playwright") as playwright,
        ):
            browser = playwright.return_value.__enter__.return_value.chromium.launch.return_value
            browser.new_page.side_effect = RuntimeError("browser execution failed")
            browser.close.side_effect = check_running
            report = resource_collector.collect_resources("https://example.test", measurement_mode="ipv4_only")
        browser.close.assert_called_once()
        self.assertFalse(proxy.is_running)
        self.assertEqual(report["navigation"]["error"], "browser execution failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
