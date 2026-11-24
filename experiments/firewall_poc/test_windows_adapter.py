import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from firewall_adapter import (
    CreatedUnverifiedError,
    ExistingRuleError,
    ExactNamePropertyConflictError,
    FirewallAdapterError,
    PowerShellResult,
    WindowsFirewallAdapter,
)


def canonical_rule():
    return {
        "exact_rule_name": "IPv6-Auditor-Experimental-test-Block-IPv6",
        "display_name": "IPv6-Auditor-Experimental-test-Block-IPv6",
        "group": "IPv6-Auditor-Experimental-test",
        "executable_path": r"C:\chrome-headless-shell.exe",
        "remote_address": "::/0",
        "direction": "Outbound",
        "action": "Block",
        "protocol": "Any",
        "mode": "ipv4_only",
    }


def query_payload(rules, count=None):
    if count is None:
        count = len(rules)
    return json.dumps({"count": count, "rules": rules})


def matching_rule(rule):
    return {
        "name": rule["exact_rule_name"],
        "display_name": rule["display_name"],
        "group": rule["group"],
        "program": rule["executable_path"],
        "remote_address": rule["remote_address"],
        "direction": rule["direction"],
        "action": rule["action"],
        "protocol": rule["protocol"],
    }


class MockPowerShellRunner:
    def __init__(self, responses=None, exc=None):
        self.responses = list(responses or [])
        self.exc = exc
        self.calls = []

    def run(self, script, timeout, env):
        self.calls.append({"script": script, "timeout": timeout, "env": dict(env)})
        if self.exc is not None:
            raise self.exc
        if not self.responses:
            raise AssertionError("Unexpected PowerShell call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class WindowsAdapterMockRunnerTests(unittest.TestCase):
    def test_successful_rule_creation_and_verification(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([])),
            PowerShellResult(0, ""),
            PowerShellResult(0, query_payload([matching_rule(rule)])),
        ])
        adapter = WindowsFirewallAdapter(runner)
        found = adapter.apply_exact(rule)
        self.assertEqual(found["name"], rule["exact_rule_name"])
        self.assertEqual(len(runner.calls), 3)
        self.assertIn("POC_RULE_NAME", runner.calls[0]["env"])
        self.assertNotIn(rule["exact_rule_name"], runner.calls[1]["script"])

    def test_rule_already_existing(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([matching_rule(rule)])),
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaisesRegex(ExistingRuleError, "ALREADY_EXISTS"):
            adapter.apply_exact(rule)
        self.assertEqual(len(runner.calls), 1)

    def test_duplicate_exact_name_results(self):
        rule = canonical_rule()
        found = matching_rule(rule)
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([found, dict(found)], 2)),
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_identity_mismatch(self):
        rule = canonical_rule()
        wrong = matching_rule(rule)
        wrong["name"] = "different-name"
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([wrong]))
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_property_mismatch(self):
        rule = canonical_rule()
        wrong = matching_rule(rule)
        wrong["protocol"] = "Tcp"
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([wrong]))
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(ExactNamePropertyConflictError):
            adapter.find_exact(rule)

    def test_successful_removal_and_absence_verification(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([matching_rule(rule)])),
            PowerShellResult(0, ""),
            PowerShellResult(0, query_payload([])),
        ])
        adapter = WindowsFirewallAdapter(runner)
        self.assertTrue(adapter.remove_exact(rule))

    def test_rule_remains_after_removal(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([matching_rule(rule)])),
            PowerShellResult(0, ""),
            PowerShellResult(0, query_payload([matching_rule(rule)])),
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.remove_exact(rule)

    def test_powerShell_timeout(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner(
            exc=FirewallAdapterError("PowerShell timed out after 30 seconds")
        )
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_nonzero_exit_code(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([])),
            PowerShellResult(1, "", "creation failed"),
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.apply_exact(rule)

    def test_invalid_json(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, "{bad")
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_empty_output(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, "")
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_missing_required_properties(self):
        rule = canonical_rule()
        incomplete = matching_rule(rule)
        incomplete.pop("protocol")
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([incomplete]))
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_application_failure_is_recorded(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([])),
            PowerShellResult(1, "", "access denied"),
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.apply_exact(rule)

    def test_cleanup_failure(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([matching_rule(rule)])),
            PowerShellResult(1, "", "cleanup failed"),
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.remove_exact(rule)

    def test_no_accidental_mock_fallback(self):
        from firewall_orchestrator import run_orchestration
        import firewall_orchestrator as orchestrator
        import firewall_controller as controller
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            with patch.object(
                orchestrator, "RECOVERY_FILE", directory / "recovery_manifest.json"
            ), patch.object(
                orchestrator, "STATE_FILE", directory / "state.json"
            ), patch.object(
                controller, "STATE_FILE", directory / "state.json"
            ):
                result = run_orchestration(
                    "ipv4_only",
                    "https://example.com",
                    dry_run=False,
                    adapter=WindowsFirewallAdapter(MockPowerShellRunner()),
                    allow_real_application=True,
                    browser_runner=lambda: {"navigation": {"completed": True}},
                )
        self.assertFalse(result["rule_applied"])
        self.assertIn("execution is disabled", result["original_exception"])
        self.assertIsNone(result["browser_report"])

    def test_creation_success_verification_failure_is_created_unverified(self):
        rule = canonical_rule()
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([])),
            PowerShellResult(0, ""),
            PowerShellResult(0, query_payload([])),
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaisesRegex(CreatedUnverifiedError, "CREATED_UNVERIFIED"):
            adapter.apply_exact(rule)

    def test_wildcard_internal_name_rejected(self):
        rule = canonical_rule()
        rule["exact_rule_name"] = "IPv6-Auditor-Experimental-*"
        rule["display_name"] = rule["exact_rule_name"]
        adapter = WindowsFirewallAdapter(MockPowerShellRunner())
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_executable_path_with_spaces_and_unicode_is_environment_only(self):
        rule = canonical_rule()
        rule["executable_path"] = r"C:\Chrome Builds\Chromium 日本語\chrome.exe"
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([])),
        ])
        adapter = WindowsFirewallAdapter(runner)
        self.assertIsNone(adapter.find_exact(rule))
        env = runner.calls[0]["env"]
        self.assertEqual(env["POC_PROGRAM"], rule["executable_path"])

    def test_multiple_remote_addresses_are_checked_as_array(self):
        rule = canonical_rule()
        found = matching_rule(rule)
        found["remote_addresses"] = ["::/0", "fe80::/10"]
        runner = MockPowerShellRunner([
            PowerShellResult(0, query_payload([found]))
        ])
        adapter = WindowsFirewallAdapter(runner)
        with self.assertRaises(FirewallAdapterError):
            adapter.find_exact(rule)

    def test_windows_powershell_stdin_argument_contract(self):
        adapter = WindowsFirewallAdapter()
        self.assertIn("-Command", [
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
            "Bypass", "-Command", "-",
        ])
        self.assertIn("-", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                           "Bypass", "-Command", "-"])
        self.assertIn("$OutputEncoding", adapter.FIND_SCRIPT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
