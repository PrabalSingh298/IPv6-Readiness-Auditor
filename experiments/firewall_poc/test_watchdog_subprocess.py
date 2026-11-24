import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from firewall_controller import build_experiment_state, proposed_rule


POC_DIRECTORY = Path(__file__).resolve().parent
WATCHDOG = POC_DIRECTORY / "watchdog_cleanup.py"
HELPER = POC_DIRECTORY / "watchdog_test_helper.py"


def valid_state(cleaned=False):
    rule = proposed_rule("ipv4_only", r"C:\chrome-headless-shell.exe")
    state = build_experiment_state("ipv4_only", rule)
    state["creation_time"] = (
        datetime.now(timezone.utc) - timedelta(seconds=120)
    ).isoformat().replace("+00:00", "Z")
    state["expiry_time"] = (
        datetime.now(timezone.utc) + timedelta(seconds=300)
    ).isoformat().replace("+00:00", "Z")
    if cleaned:
        state["cleanup_status"] = "cleaned"
    return state


def run_watchdog(state_file, recovery_file, exit_code="0"):
    state = valid_state() if state_file.exists() else None
    expiry = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat().replace("+00:00", "Z")
    count = state_file.parent / "helper-count.txt"
    log = state_file.parent / "helper.log"
    environment = dict(os.environ)
    environment["WATCHDOG_TEST_HELPER_EXIT"] = exit_code
    environment["WATCHDOG_TEST_HELPER_COUNT"] = str(count)
    environment["WATCHDOG_TEST_HELPER_LOG"] = str(log)
    return subprocess.run(
        [
            sys.executable,
            str(WATCHDOG),
            "--state-file",
            str(state_file),
            "--recovery-file",
            str(recovery_file),
            "--expiry",
            expiry,
            "--test-mode",
            "--cleanup-helper",
            str(HELPER),
            "--log-file",
            str(log),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env=environment,
    ), count


class WatchdogSubprocessTests(unittest.TestCase):
    def test_valid_primary_state(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            state_file.write_text(
                __import__("json").dumps(valid_state()),
                encoding="utf-8",
            )
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(count.read_text(encoding="utf-8"), "1")

    def test_missing_primary_valid_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            recovery_file.write_text(
                __import__("json").dumps(valid_state()),
                encoding="utf-8",
            )
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(state_file.is_file())
            self.assertEqual(count.read_text(encoding="utf-8"), "1")

    def test_corrupted_primary_valid_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            state_file.write_text("{bad", encoding="utf-8")
            recovery_file.write_text(
                __import__("json").dumps(valid_state()),
                encoding="utf-8",
            )
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(count.read_text(encoding="utf-8"), "1")

    def test_already_cleaned_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            state_file.write_text(
                __import__("json").dumps(valid_state(cleaned=True)),
                encoding="utf-8",
            )
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(count.exists())

    def test_both_files_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 5)
            self.assertFalse(count.exists())

    def test_both_files_corrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            state_file.write_text("{bad", encoding="utf-8")
            recovery_file.write_text("{bad", encoding="utf-8")
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 5)
            self.assertFalse(count.exists())

    def test_helper_failure_is_retried_once(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            state_file.write_text(
                __import__("json").dumps(valid_state()),
                encoding="utf-8",
            )
            result, count = run_watchdog(state_file, recovery_file, "7")
            self.assertEqual(result.returncode, 3)
            self.assertEqual(count.read_text(encoding="utf-8"), "2")

    def test_expired_recovery_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            manifest = valid_state()
            manifest["creation_time"] = "1999-12-31T23:59:00Z"
            manifest["expiry_time"] = "2000-01-01T00:00:00Z"
            recovery_file.write_text(
                __import__("json").dumps(manifest),
                encoding="utf-8",
            )
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 5)
            self.assertFalse(count.exists())

    def test_incomplete_recovery_watchdog_metadata_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            state_file = directory / "state.json"
            recovery_file = directory / "recovery_manifest.json"
            manifest = valid_state()
            manifest["watchdog"] = {"started": False}
            recovery_file.write_text(
                __import__("json").dumps(manifest),
                encoding="utf-8",
            )
            result, count = run_watchdog(state_file, recovery_file)
            self.assertEqual(result.returncode, 5)
            self.assertFalse(count.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
