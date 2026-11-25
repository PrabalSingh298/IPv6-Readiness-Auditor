import unittest

from backend.measurement.readiness import calculate_readiness, classify_dns_capability


def resource(url, *, v4=False, v6=False, failure=None, success=None, network=False):
    return {
        "url": url,
        "success": success,
        "http_status": 200 if success else None,
        "raw_evidence": {"response": {"from_network": network}},
        "ip_evidence": {
            "resolved_addresses": {"ipv4": ["192.0.2.1"] if v4 else [],
                                   "ipv6": ["2001:db8::1"] if v6 else [], "failure_reason": failure},
            "proxy_origin": {"connected_peers": [{"family": "ipv6"}] if v6 else []},
        },
    }


class ReadinessTests(unittest.TestCase):
    def test_dns_and_http_scores_from_unique_baseline_urls(self):
        baseline = {"measurement_id": "base", "resources": [
            resource("https://site.test/", v4=True, v6=True, success=False),
            resource("https://SITE.test:443/#anchor", v4=True, v6=True),
            resource("https://site.test/pixel?a=1", v4=True),
            resource("https://site.test/pixel?a=2", v6=True),
            resource("https://unknown.test/", v4=True, failure="dns_timeout"),
            resource("data:image/png;base64,AA", v6=True),
            resource("blob:https://site.test/id", v6=True),
        ]}
        ipv6 = {"measurement_id": "v6", "measurement_mode": "ipv6_only",
                "network_enforcement_mechanism": "socks5_ip_family_proxy", "navigation": {"attempted": True},
                "resources": [
                    resource("https://site.test", success=True, v6=True, network=True),
                    resource("https://site.test/pixel?a=1", success=False),
                    resource("https://unknown.test/", success=True, v6=True, network=False),
                    resource("https://site.test/extra", success=True, v6=True, network=True),
                ]}
        dns_only = calculate_readiness(baseline)
        self.assertEqual(dns_only["dns_counts"], {"ipv4_only": 1, "dual_stack": 1, "ipv6_only": 1, "unknown": 1})
        self.assertEqual(dns_only["total_baseline_resources"], 4)
        self.assertEqual(dns_only["dns_ipv6_readiness_percent"], 50)
        self.assertIsNone(dns_only["http_ipv6_readiness_percent"])
        paired = calculate_readiness(baseline, ipv6)
        self.assertEqual(paired["http_ipv6_readiness_percent"], 25)
        self.assertEqual(paired["http_outcome_counts"], {"retrieved": 1, "failed": 1, "undiscovered": 1, "unverified": 1})

    def test_unknown_empty_and_unperformed_measurements(self):
        for failure in ("dns_failure", "dns_timeout", "dns_cancelled"):
            self.assertEqual(classify_dns_capability(resource("https://site.test", v6=True, failure=failure)), "unknown")
        self.assertIsNone(calculate_readiness({})["dns_ipv6_readiness_percent"])
        baseline = {"resources": [resource("https://site.test", v6=True)]}
        ipv6 = {"measurement_mode": "ipv6_only", "network_enforcement_mechanism": "socks5_ip_family_proxy",
                "navigation": {"attempted": False}}
        self.assertIsNone(calculate_readiness(baseline, ipv6)["http_ipv6_readiness_percent"])
        ipv6["navigation"]["attempted"] = True
        self.assertEqual(calculate_readiness(baseline, ipv6)["http_ipv6_readiness_percent"], 0)
