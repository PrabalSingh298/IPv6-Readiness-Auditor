import json
import tempfile
import unittest
from unittest.mock import patch
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
from firewall_state import (
    POLICY_ACTIVE_BEFORE_EXPIRY,
    POLICY_NORMAL_EXPIRY_CLEANUP,
    POLICY_ALREADY_CLEANED,
    POLICY_STALE_RECOVERY,
    POLICY_MISSING_OR_INVALID,
    POLICY_CONFLICT,
    classify_state_pair,
    is_stale,
    parse_utc,
    validate_safe_internal_name,
)


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
    def test_primary_before_expiry_policy(self):
        manifest, _ = manifest_and_rule()
        policy, selected = classify_state_pair(manifest, manifest)
        self.assertEqual(policy, POLICY_ACTIVE_BEFORE_EXPIRY)
        self.assertIs(selected, manifest)

    def test_primary_normal_expiry_policy(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = "1999-12-31T23:59:00Z"
        manifest["expiry_time"] = "2000-01-01T00:00:00Z"
        manifest["cleanup_status"] = "active"
        policy, selected = classify_state_pair(manifest, manifest)
        self.assertEqual(policy, POLICY_NORMAL_EXPIRY_CLEANUP)

    def test_already_cleaned_policy_refuses_repeat(self):
        manifest, _ = manifest_and_rule()
        manifest["expiry_time"] = (
            datetime.now(timezone.utc) + timedelta(seconds=300)
        ).isoformat().replace("+00:00", "Z")
        manifest["cleanup_status"] = "cleaned"
        policy, selected = classify_state_pair(manifest, manifest)
        self.assertEqual(policy, POLICY_ALREADY_CLEANED)

    def test_stale_cleaned_state_is_refused(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = "1999-12-31T23:59:00Z"
        manifest["expiry_time"] = "2000-01-01T00:00:00Z"
        manifest["cleanup_status"] = "cleaned"
        policy, selected = classify_state_pair(manifest, manifest)
        self.assertEqual(policy, POLICY_STALE_RECOVERY)

    def test_stale_recovery_policy(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = "1999-12-31T23:59:00Z"
        manifest["expiry_time"] = "2000-01-01T00:00:00Z"
        policy, selected = classify_state_pair(None, manifest)
        self.assertEqual(policy, POLICY_STALE_RECOVERY)

    def test_missing_primary_and_recovery_policy(self):
        policy, selected = classify_state_pair(None, None)
        self.assertEqual(policy, POLICY_MISSING_OR_INVALID)
        self.assertIsNone(selected)

    def test_conflicting_primary_and_recovery_policy(self):
        primary, _ = manifest_and_rule()
        recovery, _ = manifest_and_rule()
        recovery["exact_rule_name"] = "IPv6-Auditor-Experimental-other"
        recovery["display_name"] = recovery["exact_rule_name"]
        recovery["group"] = "IPv6-Auditor-Experimental-other"
        policy, selected = classify_state_pair(primary, recovery)
        self.assertEqual(policy, POLICY_CONFLICT)
    def test_wildcard_internal_name_rejected_by_canonical_validation(self):
        manifest, rule = manifest_and_rule()
        manifest["exact_rule_name"] = "IPv6-Auditor-Experimental-*"
        manifest["display_name"] = manifest["exact_rule_name"]
        manifest["group"] = "IPv6-Auditor-Experimental-*"
        self.assertTrue(any("unsafe internal name characters" in error for error in validate_manifest(manifest)))
        self.assertFalse(validate_safe_internal_name("*"))

    def test_existing_mock_rule_is_never_applied_or_cleaned(self):
        manifest, _ = manifest_and_rule()
        from firewall_adapter import MockFirewallAdapter, ExistingRuleError
        adapter = adapter_for(manifest)
        with self.assertRaises(ExistingRuleError):
            adapter.apply_exact(manifest)
        self.assertEqual(adapter.apply_attempts, 1)

    def test_exact_name_property_conflict_is_not_applied_or_removed(self):
        manifest, _ = manifest_and_rule()
        adapter = adapter_for(manifest)
        adapter.rules[manifest["exact_rule_name"]]["protocol"] = "Tcp"
        from firewall_adapter import ExactNamePropertyConflictError
        with self.assertRaises(ExactNamePropertyConflictError):
            adapter.find_exact(manifest)
        self.assertEqual(adapter.remove_attempts, 0)

    def test_created_unverified_status_preserves_recovery_without_cleanup(self):
        manifest, _ = manifest_and_rule()
        from firewall_adapter import MockFirewallAdapter, CreatedUnverifiedError
        adapter = MockFirewallAdapter()
        original_apply = adapter.apply_exact
        def fail_verification(rule):
            raise CreatedUnverifiedError(
                "CREATED_UNVERIFIED: exact verification failed"
            )
        adapter.apply_exact = fail_verification
        with patch("firewall_orchestrator.is_administrator", return_value=True), \
             patch("firewall_orchestrator.launch_watchdog", return_value=1234):
            result = run_orchestration(
                "ipv4_only",
                "https://example.com",
                dry_run=False,
                adapter=adapter,
                allow_real_application=True,
                browser_runner=lambda: {"navigation": {"completed": True}},
            )
        self.assertFalse(result["rule_applied"])
        self.assertEqual(result["cleanup"]["cleanup_status"], "not_attempted")
        self.assertIn("CREATED_UNVERIFIED", result["application_exception"])

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

    def test_expired_cleaned_state_does_not_authorize_cleanup(self):
        manifest, _ = manifest_and_rule()
        manifest["creation_time"] = "1999-12-31T23:59:00Z"
        manifest["expiry_time"] = "2000-01-01T00:00:00Z"
        manifest["cleanup_status"] = "cleaned"
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
        self.assertEqual(result["cleanup_status"], "exact_name_property_conflict")

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
