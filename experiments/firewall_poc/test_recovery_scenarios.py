import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from firewall_adapter import MockFirewallAdapter
from firewall_orchestrator import (
    build_recovery_manifest,
    cleanup_with_adapter,
    load_json,
    run_orchestration,
    validate_manifest,
)
from firewall_controller import proposed_rule, validate_experiment_state, is_stale_state
from firewall_state import is_stale, parse_utc


def manifest_and_rule():
    rule = proposed_rule("ipv4_only", r"C:\chrome-headless-shell.exe")
    manifest = build_recovery_manifest("ipv4_only", rule)
    return manifest, rule


def adapter_for(manifest, **kwargs):
    rule = {
        "name": manifest["exact_rule_name"],
        "display_name": manifest["display_name"],
        "group": manifest["group"],
        "program": manifest["executable_path"],
        "remote_address": manifest["remote_address"],
        "direction": manifest["direction"],
        "action": manifest["action"],
        "protocol": manifest["protocol"],
    }
    return MockFirewallAdapter(rules=[rule], **kwargs)


class RecoveryScenarioTests(unittest.TestCase):
    def test_valid_utc_timestamp(self):
        manifest, _ = manifest_and_rule()
        parsed = parse_utc("2026-11-24T19:00:00Z")
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertEqual(validate_manifest(manifest), [])

    def test_valid_non_utc_offset_timestamp(self):
        parsed = parse_utc("2026-11-24T19:00:00+05:30")
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_timestamp_missing_timezone_rejected(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = "2026-11-24T19:00:00"
        self.assertIn("invalid creation or expiry timestamp", validate_manifest(manifest))

    def test_invalid_timestamp_rejected(self):
        manifest, _ = manifest_and_rule()
        manifest["expiry_time"] = "not-a-timestamp"
        self.assertIn("invalid creation or expiry timestamp", validate_manifest(manifest))

    def test_reversed_timestamp_rejected(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = "2026-11-24T20:00:00Z"
        manifest["expiry_time"] = "2026-11-24T19:00:00Z"
        self.assertIn("expiry_time precedes creation_time", validate_manifest(manifest))

    def test_valid_watchdog_metadata(self):
        manifest, _ = manifest_and_rule()
        manifest["watchdog"] = {"process_id": 1234, "started": True, "status": "running"}
        self.assertEqual(validate_manifest(manifest), [])

    def test_watchdog_missing_fields_rejected(self):
        manifest, _ = manifest_and_rule()
        manifest["watchdog"] = {"process_id": None, "started": False}
        self.assertTrue(any("missing watchdog field" in error for error in validate_manifest(manifest)))

    def test_watchdog_invalid_pid_rejected(self):
        manifest, _ = manifest_and_rule()
        manifest["watchdog"] = {"process_id": -1, "started": True, "status": "running"}
        self.assertIn("invalid watchdog process_id", validate_manifest(manifest))

    def test_watchdog_dry_run_metadata_rejected(self):
        manifest, _ = manifest_and_rule()
        manifest["watchdog"] = {"process_id": 12, "started": True, "status": "dry_run"}
        self.assertIn("inconsistent dry-run watchdog metadata", validate_manifest(manifest))

    def test_normal_completion(self):
        result = run_orchestration(
            "ipv4_only", "https://example.com", dry_run=True,
            browser_runner=lambda: {"navigation": {"completed": True}},
        )
        self.assertEqual(result["manifest"]["final_status"], "completed")
        self.assertEqual(result["cleanup"]["cleanup_status"], "not_attempted")
        self.assertFalse(result["rule_applied"])

    def test_browser_navigation_failure(self):
        result = run_orchestration(
            "ipv4_only", "https://example.com", dry_run=True,
            browser_runner=lambda: (_ for _ in ()).throw(RuntimeError("navigation failed")),
        )
        self.assertEqual(result["manifest"]["final_status"], "browser_failed")
        self.assertEqual(result["cleanup"]["cleanup_status"], "not_attempted")

    def test_python_exception(self):
        def raise_exception():
            raise ValueError("unexpected process exception")

        result = run_orchestration(
            "ipv4_only", "https://example.com", dry_run=True,
            browser_runner=raise_exception,
        )
        self.assertIn("ValueError", result["browser_report"]["error"])
        self.assertEqual(result["cleanup"]["cleanup_status"], "not_attempted")

    def test_cleanup_failure_without_rule_removal(self):
        manifest, _ = manifest_and_rule()
        adapter = adapter_for(manifest)
        adapter.removal_fails = True
        result = cleanup_with_adapter(manifest, adapter)
        self.assertEqual(result["cleanup_status"], "failed")
        self.assertFalse(result["verified_absent"])

    def test_one_bounded_retry(self):
        manifest, _ = manifest_and_rule()
        adapter = adapter_for(manifest)
        original_remove = adapter.remove_exact

        def fail_once(rule):
            if adapter.remove_attempts == 0:
                adapter.remove_attempts += 1
                return False
            return original_remove(rule)

        adapter.remove_exact = fail_once
        result = cleanup_with_adapter(manifest, adapter)
        self.assertEqual(result["cleanup_status"], "cleaned")
        self.assertEqual(result["attempts"], 2)

    def test_rule_still_present_after_removal(self):
        manifest, _ = manifest_and_rule()
        adapter = adapter_for(manifest, remain_after_remove=True)
        result = cleanup_with_adapter(manifest, adapter)
        self.assertEqual(result["cleanup_status"], "failed")
        self.assertFalse(result["verified_absent"])
        self.assertEqual(adapter.remove_attempts, 2)

    def test_exact_rule_identity_mismatch(self):
        manifest, _ = manifest_and_rule()
        adapter = adapter_for(manifest)
        adapter.rules.clear()
        adapter.rules["different-internal-name"] = {
            "name": "different-internal-name",
            "display_name": manifest["display_name"],
            "group": manifest["group"],
            "program": manifest["executable_path"],
            "remote_address": manifest["remote_address"],
            "direction": manifest["direction"],
            "action": manifest["action"],
            "protocol": manifest["protocol"],
        }
        result = cleanup_with_adapter(manifest, adapter)
        self.assertEqual(result["cleanup_status"], "failed")
        self.assertEqual(result["attempts"], 0)

    def test_missing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "state.json"
            self.assertIsNone(load_json(missing))

    def test_corrupted_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text("{bad json", encoding="utf-8")
            self.assertIsNone(load_json(state))

    def test_missing_recovery_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = load_json(Path(directory) / "recovery_manifest.json")
            self.assertIsNone(manifest)
            self.assertNotEqual(validate_manifest(manifest), [])

    def test_repeated_cleanup(self):
        manifest, _ = manifest_and_rule()
        adapter = adapter_for(manifest)
        first = cleanup_with_adapter(manifest, adapter)
        second = cleanup_with_adapter(manifest, adapter)
        self.assertEqual(first["cleanup_status"], "cleaned")
        self.assertEqual(second["cleanup_status"], "cleaned")
        self.assertEqual(second["attempts"], 0)

    def test_watchdog_timeout(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = (
            datetime.now(timezone.utc) - timedelta(seconds=120)
        ).isoformat().replace("+00:00", "Z")
        manifest["expiry_time"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.assertTrue(validate_manifest(manifest) == [])
        self.assertLess(manifest["expiry_time"], "2099")

    def test_watchdog_startup_failure(self):
        manifest, _ = manifest_and_rule()
        manifest["cleanup_status"] = "watchdog_failed"
        manifest["final_status"] = "refused_watchdog_failed"
        self.assertEqual(manifest["cleanup_status"], "watchdog_failed")

    def test_watchdog_privilege_failure(self):
        manifest, _ = manifest_and_rule()
        manifest["cleanup_status"] = "not_attempted"
        manifest["final_status"] = "refused_no_administrator"
        self.assertEqual(manifest["final_status"], "refused_no_administrator")

    def test_stale_state(self):
        manifest, rule = manifest_and_rule()
        manifest["creation_time"] = "1999-12-31T23:59:00Z"
        manifest["expiry_time"] = "2000-01-01T00:00:00Z"
        state = dict(manifest)
        state["expiry_time"] = manifest["expiry_time"]
        state["cleanup_status"] = "active"
        self.assertEqual(validate_experiment_state(state), [])
        self.assertTrue(is_stale_state(state))

    def test_expired_recovery_manifest_is_stale(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = "1999-12-31T23:59:00Z"
        manifest["expiry_time"] = "2000-01-01T00:00:00Z"
        self.assertTrue(is_stale(manifest))

    def test_inconsistent_recovery_manifest_is_invalid(self):
        manifest, _ = manifest_and_rule()
        manifest["remote_address"] = "0.0.0.0/0"
        self.assertIn("remote address does not match firewall mode", validate_manifest(manifest))

    def test_dry_run_operation(self):
        result = run_orchestration(
            "ipv6_only", "https://ipv6.google.com", dry_run=True,
            browser_runner=lambda: {"navigation": {"completed": True}},
        )
        self.assertTrue(result["dry_run"])
        self.assertIsNone(result["watchdog_pid"])
        self.assertEqual(result["cleanup"]["cleanup_status"], "not_attempted")

    def test_rule_properties_mismatch_refuses_cleanup(self):
        manifest, _ = manifest_and_rule()
        adapter = adapter_for(manifest)
        adapter.rules[manifest["exact_rule_name"]]["protocol"] = "Tcp"
        result = cleanup_with_adapter(manifest, adapter)
        self.assertEqual(result["cleanup_status"], "failed")

    def test_initial_state_write_exception_is_recorded_separately(self):
        import firewall_orchestrator as orchestrator

        original_atomic = orchestrator.atomic_json
        def fail_initial_write(path, value):
            raise OSError("filesystem unavailable")

        orchestrator.atomic_json = fail_initial_write
        try:
            result = orchestrator.run_orchestration(
                "ipv4_only",
                "https://example.com",
                dry_run=True,
                browser_runner=lambda: {"navigation": {"completed": True}},
            )
        finally:
            orchestrator.atomic_json = original_atomic

        self.assertIn("filesystem unavailable", result["state_write_exception"])
        self.assertFalse(result["rule_applied"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
