import json
import tempfile
import unittest
from pathlib import Path

from firewall_controller import (
    is_administrator,
    headless_shell_executable,
    powershell_rule_command,
    proposed_rule,
    validate_executable,
)
from verify_connections import verify
from browser_probe import (
    compare_observations,
    normalize_server_address,
)


class FirewallPoCTests(unittest.TestCase):
    def test_ipv4_rule_blocks_ipv6_range(self):
        rule = proposed_rule("ipv4_only", r"C:\chrome-headless-shell.exe")
        self.assertEqual(rule["remote_address"], "::/0")
        command = powershell_rule_command(rule)
        self.assertIn("-Direction Outbound", command)
        self.assertIn("-Action Block", command)
        self.assertIn(r"-Protocol Any", command)
        self.assertIn(r"-Program 'C:\chrome-headless-shell.exe'", command)

    def test_ipv6_rule_blocks_ipv4_range(self):
        rule = proposed_rule("ipv6_only", r"C:\chrome-headless-shell.exe")
        self.assertEqual(rule["remote_address"], "0.0.0.0/0")
        command = powershell_rule_command(rule)
        self.assertIn("-Protocol Any", command)
        self.assertIn(r"-Program 'C:\chrome-headless-shell.exe'", command)

    def test_headless_shell_default_contains_verified_name(self):
        executable = headless_shell_executable()
        self.assertTrue(executable.endswith(r"chrome-headless-shell.exe"))
        self.assertIn("chromium_headless_shell-", executable)

    def test_configurable_executable_is_returned_verbatim(self):
        configured = r"C:\custom\chrome-headless-shell.exe"
        self.assertEqual(headless_shell_executable(configured), configured)

    def test_missing_executable_is_rejected(self):
        missing = r"C:\definitely-missing\chrome-headless-shell.exe"
        with self.assertRaises(FileNotFoundError):
            validate_executable(missing)

    def test_cleanup_requires_unique_name_and_group(self):
        script = Path(__file__).with_name("cleanup_firewall_rules.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("IPv6-Auditor-Experimental-", script)
        self.assertIn("$TrackedName.StartsWith", script)
        self.assertIn("$_.Group -eq $TrackedGroup", script)

    def test_unknown_remote_peer_is_inconclusive(self):
        result = verify({
            "requested_mode": "ipv4_only",
            "remote_peer_observations": [],
        })
        self.assertEqual(result["status"], "inconclusive")

    def test_ipv4_only_accepts_only_observed_ipv4(self):
        report = {
            "requested_mode": "ipv4_only",
            "remote_peer_observations": [
                {"address": "104.20.23.154", "address_family": "ipv4"}
            ],
        }
        self.assertEqual(verify(report)["status"], "verified")

    def test_ipv6_only_rejects_mixed_observations(self):
        report = {
            "requested_mode": "ipv6_only",
            "remote_peer_observations": [
                {"address": "2606:4700:10::6814:179a", "address_family": "ipv6"},
                {"address": "104.20.23.154", "address_family": "ipv4"},
            ],
        }
        self.assertEqual(verify(report)["status"], "failed_or_mixed")

    def test_dry_run_does_not_adopt_admin_state(self):
        self.assertIn(is_administrator(), (True, False))

    def test_none_server_address_is_unknown(self):
        observation = normalize_server_address(None)
        self.assertFalse(observation["available"])
        self.assertEqual(observation["address_family"], "unknown")

    def test_server_address_tuple_has_ipv6_family(self):
        observation = normalize_server_address(("2606:4700:10::6814:179a", 443))
        self.assertTrue(observation["available"])
        self.assertEqual(observation["ip"], "2606:4700:10::6814:179a")
        self.assertEqual(observation["port"], 443)
        self.assertEqual(observation["address_family"], "ipv6")

    def test_bracketed_server_address_is_normalized(self):
        observation = normalize_server_address(("[2606:4700:90c5:72db:f23b:20:ef6b:ff98]", 443))
        self.assertEqual(
            observation["ip"],
            "2606:4700:90c5:72db:f23b:20:ef6b:ff98",
        )
        self.assertEqual(observation["address_family"], "ipv6")

    def test_playwright_and_cdp_comparison(self):
        playwright_observation = normalize_server_address(("104.20.23.154", 443))
        cdp_observation = {
            "available": True,
            "ip": "104.20.23.154",
            "address_family": "ipv4",
        }
        self.assertEqual(
            compare_observations(playwright_observation, cdp_observation)["status"],
            "agree",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
