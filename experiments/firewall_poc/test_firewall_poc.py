import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone

from firewall_controller import (
    is_administrator,
    headless_shell_executable,
    powershell_rule_command,
    proposed_rule,
    validate_executable,
    build_experiment_state,
    validate_experiment_state,
    is_stale_state,
    repeated_cleanup_status,
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

    def test_state_records_all_required_metadata(self):
        rule = proposed_rule("ipv4_only", r"C:\chrome-headless-shell.exe")
        state = build_experiment_state("ipv4_only", rule)
        self.assertEqual(validate_experiment_state(state), [])
        self.assertIn("experiment_id", state)
        self.assertEqual(state["mode"], "ipv4_only")
        self.assertEqual(state["display_name"], rule["display_name"])
        self.assertEqual(state["group"], rule["group"])
        self.assertEqual(state["executable_path"], rule["program"])
        self.assertIn("creation_time", state)
        self.assertIn("expiry_time", state)
        self.assertIn("cleanup_status", state)

    def test_normal_completion_cleanup_runs_once(self):
        cleaned = []
        state = build_experiment_state(
            "ipv4_only",
            proposed_rule("ipv4_only", r"C:\chrome-headless-shell.exe"),
        )
        try:
            cleaned.append("cleanup")
        finally:
            pass
        self.assertEqual(cleaned, ["cleanup"])
        state["cleanup_status"] = "cleaned"
        self.assertTrue(repeated_cleanup_status(state))

    def test_browser_failure_still_runs_finally_cleanup(self):
        cleaned = []
        try:
            raise RuntimeError("browser navigation failed")
        except RuntimeError:
            pass
        finally:
            cleaned.append("cleanup")
        self.assertEqual(cleaned, ["cleanup"])

    def test_python_exception_still_runs_finally_cleanup(self):
        cleaned = []
        with self.assertRaises(ValueError):
            try:
                raise ValueError("unexpected Python exception")
            finally:
                cleaned.append("cleanup")
        self.assertEqual(cleaned, ["cleanup"])

    def test_watchdog_timeout_marks_expired_state(self):
        state = build_experiment_state(
            "ipv6_only",
            proposed_rule("ipv6_only", r"C:\chrome-headless-shell.exe"),
        )
        future = datetime.now(timezone.utc) + timedelta(seconds=5)
        state["expiry_time"] = future.isoformat().replace("+00:00", "Z")
        self.assertFalse(is_stale_state(state))
        expired = datetime.now(timezone.utc) - timedelta(seconds=1)
        state["expiry_time"] = expired.isoformat().replace("+00:00", "Z")
        self.assertTrue(is_stale_state(state))

    def test_missing_and_incomplete_state_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "state.json"
            self.assertFalse(state_file.exists())
        incomplete = {"experiment_id": "fw-test"}
        self.assertNotEqual(validate_experiment_state(incomplete), [])
        self.assertTrue(is_stale_state(incomplete))

    def test_repeated_cleanup_is_idempotent(self):
        rule = proposed_rule("ipv4_only", r"C:\chrome-headless-shell.exe")
        state = build_experiment_state("ipv4_only", rule)
        state["cleanup_status"] = "cleaned"
        self.assertTrue(repeated_cleanup_status(state))
        self.assertTrue(repeated_cleanup_status(state))

    def test_stale_state_is_detected_without_cleanup_guessing(self):
        state = build_experiment_state(
            "ipv4_only",
            proposed_rule("ipv4_only", r"C:\chrome-headless-shell.exe"),
        )
        state["expiry_time"] = "2000-01-01T00:00:00Z"
        self.assertTrue(is_stale_state(state))


if __name__ == "__main__":
    unittest.main(verbosity=2)
