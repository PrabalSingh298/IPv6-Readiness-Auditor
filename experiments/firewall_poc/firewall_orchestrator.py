import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from firewall_controller import (
    build_experiment_state,
    headless_shell_executable,
    is_administrator,
    launch_watchdog,
    proposed_rule,
    save_tracked_rules,
    validate_executable,
    validate_experiment_state,
)
from firewall_adapter import (
    CreatedUnverifiedError,
    ExistingRuleError,
    ExactNamePropertyConflictError,
    MockFirewallAdapter,
    WindowsFirewallAdapter,
)
REAL_FIREWALL_APPLICATION_ENABLED = False
from firewall_state import (
    SCHEMA_VERSION,
    atomic_json,
    iso_utc,
    load_json,
    validate_canonical_state,
)


EXPERIMENT_DIRECTORY = Path(__file__).resolve().parent
STATE_FILE = EXPERIMENT_DIRECTORY / "state.json"
RECOVERY_FILE = EXPERIMENT_DIRECTORY / "recovery_manifest.json"
WATCHDOG_LOG = EXPERIMENT_DIRECTORY / "watchdog.log"



def validate_manifest(manifest):
    return validate_canonical_state(manifest)


def sync_lifecycle_state(manifest):
    errors = validate_canonical_state(manifest)
    if errors:
        raise RuntimeError("invalid lifecycle state: " + "; ".join(errors))
    atomic_json(RECOVERY_FILE, manifest)
    save_tracked_rules(manifest)


def build_recovery_manifest(mode, rule, duration_seconds=900):
    created = datetime.now(timezone.utc)
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": f"fw-{created.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}",
        "mode": mode,
        "exact_rule_name": rule["exact_rule_name"],
        "display_name": rule["display_name"],
        "group": rule["group"],
        "executable_path": rule["program"],
        "remote_address": rule["remote_address"],
        "direction": rule["direction"],
        "action": rule["action"],
        "protocol": rule["protocol"],
        "creation_time": iso_utc(created),
        "expiry_time": iso_utc(created + timedelta(seconds=duration_seconds)),
        "creation_status": "preserved",
        "application_status": "pending",
        "cleanup_status": "pending",
        "cleanup_verified_absent": False,
        "cleanup_persistence_status": "pending",
        "watchdog": {
            "process_id": None,
            "started": False,
            "status": "pending",
        },
        "final_status": "pending",
    }


def execute_browser_measurement(url):
    command = [
        sys.executable,
        str(EXPERIMENT_DIRECTORY / "browser_probe.py"),
        "--mode",
        "unrestricted",
        "--url",
        url,
        "--disable-quic",
        "--output",
        str(EXPERIMENT_DIRECTORY / "dry_run_browser_report.json"),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Browser probe failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"navigation": {"completed": False, "error": "invalid browser report JSON"}}


def cleanup_with_adapter(manifest, adapter, retries=1):
    try:
        found = adapter.find_exact(manifest)
    except ExactNamePropertyConflictError as error:
        return {
            "cleanup_status": "exact_name_property_conflict",
            "attempts": 0,
            "verified_absent": False,
            "error": str(error),
        }
    if found is None:
        return {"cleanup_status": "cleaned", "attempts": 0, "verified_absent": True}
    if found in ("MISMATCH", "EXACT_NAME_PROPERTY_CONFLICT"):
        return {"cleanup_status": "failed", "attempts": 0, "verified_absent": False,
                "error": "exact rule identity or property conflict"}
    if hasattr(adapter, "matches_properties") and not adapter.matches_properties(found, manifest):
        return {"cleanup_status": "failed", "attempts": 0, "verified_absent": False,
                "error": "rule properties mismatch"}

    attempts = 0
    while attempts <= retries:
        attempts += 1
        try:
            adapter.remove_exact(manifest)
        except Exception as error:
            last_error = str(error)
        else:
            last_error = None
        if adapter.verify_absent(manifest):
            return {"cleanup_status": "cleaned", "attempts": attempts,
                    "verified_absent": True}
    return {"cleanup_status": "failed", "attempts": attempts,
            "verified_absent": False,
            "error": last_error or "rule remained present after removal"}


def run_orchestration(
    mode,
    url,
    dry_run=True,
    adapter=None,
    browser_runner=None,
    allow_real_application=False,
):
    manifest = None
    original_exception = None
    application_exception = None
    browser_exception = None
    cleanup_exception = None
    state_write_exception = None
    browser_report = None
    cleanup_result = None
    rule_applied = False
    watchdog_pid = None

    try:
        if mode not in ("ipv4_only", "ipv6_only"):
            raise ValueError("Mode must be ipv4_only or ipv6_only")
        executable = headless_shell_executable()
        validate_executable(executable)
        rule = proposed_rule(mode, executable)
        manifest = build_recovery_manifest(mode, rule)
        manifest_errors = validate_manifest(manifest)
        if manifest_errors:
            raise RuntimeError("invalid recovery manifest: " + "; ".join(manifest_errors))

        try:
            sync_lifecycle_state(manifest)
        except BaseException as error:
            state_write_exception = f"{type(error).__name__}: {error}"
            raise

        if not dry_run:
            if not allow_real_application:
                raise RuntimeError(
                    "Real firewall application is disabled; explicit opt-in is required"
                )
            if isinstance(adapter, WindowsFirewallAdapter):
                if not REAL_FIREWALL_APPLICATION_ENABLED:
                    raise RuntimeError(
                        "WindowsFirewallAdapter is implemented but execution is disabled"
                    )
            elif not isinstance(adapter, MockFirewallAdapter):
                raise RuntimeError("No fallback adapter is permitted")
            if not is_administrator():
                raise PermissionError("Administrator privileges are required")
            watchdog_pid = launch_watchdog(manifest)
            if watchdog_pid is None:
                raise RuntimeError("watchdog startup failed")
            manifest["watchdog"] = {
                "process_id": watchdog_pid,
                "started": True,
                "status": "running",
            }
            manifest["cleanup_status"] = "active"
            try:
                sync_lifecycle_state(manifest)
            except BaseException as error:
                state_write_exception = f"{type(error).__name__}: {error}"
                raise

            try:
                adapter.apply_exact(manifest)
                verified = adapter.find_exact(manifest)
                if verified is None:
                    raise RuntimeError(
                        "Rule application succeeded without a verified exact rule"
                    )
                if hasattr(adapter, "matches_properties") and not adapter.matches_properties(verified, manifest):
                    raise RuntimeError("Applied rule failed property verification")
                rule_applied = True
                manifest["creation_status"] = "active"
                manifest["application_status"] = "active"
                manifest["cleanup_status"] = "active"
                try:
                    sync_lifecycle_state(manifest)
                except BaseException as sync_error:
                    state_write_exception = f"{type(sync_error).__name__}: {sync_error}"
                    manifest["cleanup_status"] = "failed"
                    manifest["application_status"] = "application_failed"
                    raise
            except BaseException as error:
                application_exception = f"{type(error).__name__}: {error}"
                if isinstance(error, ExistingRuleError):
                    manifest["cleanup_status"] = "already_exists"
                    manifest["application_status"] = "already_exists"
                elif isinstance(error, CreatedUnverifiedError):
                    manifest["cleanup_status"] = "created_unverified"
                    manifest["application_status"] = "created_unverified"
                elif isinstance(error, ExactNamePropertyConflictError):
                    manifest["cleanup_status"] = "exact_name_property_conflict"
                    manifest["application_status"] = "exact_name_property_conflict"
                else:
                    manifest["cleanup_status"] = "failed"
                    manifest["application_status"] = "application_failed"
                try:
                    sync_lifecycle_state(manifest)
                except BaseException as sync_error:
                    state_write_exception = f"{type(sync_error).__name__}: {sync_error}"
                raise

        if dry_run:
            manifest["watchdog"] = {
                "process_id": None,
                "started": False,
                "status": "dry_run",
            }
            sync_lifecycle_state(manifest)

        browser = browser_runner or (lambda: execute_browser_measurement(url))
        try:
            browser_report = browser()
            manifest["final_status"] = "browser_completed"
        except BaseException as error:
            browser_exception = f"{type(error).__name__}: {error}"
            browser_report = {"error": browser_exception}
            manifest["final_status"] = "browser_failed"
            original_exception = browser_exception

    except BaseException as error:
        if original_exception is None:
            original_exception = f"{type(error).__name__}: {error}"
        if application_exception is None and isinstance(error, PermissionError):
            application_exception = original_exception
        if manifest is not None:
            if browser_exception is None:
                manifest["final_status"] = "initialization_or_application_failed"
    finally:
        if rule_applied:
            try:
                cleanup_result = cleanup_with_adapter(
                    manifest,
                    adapter,
                    retries=1,
                )
                manifest["cleanup_status"] = cleanup_result["cleanup_status"]
                manifest["cleanup_attempts"] = cleanup_result["attempts"]
                manifest["cleanup_verified_absent"] = cleanup_result["verified_absent"]
                if cleanup_result["cleanup_status"] != "cleaned":
                    cleanup_exception = cleanup_result.get("error", "cleanup failed")
            except BaseException as error:
                cleanup_exception = f"{type(error).__name__}: {error}"
                manifest["cleanup_status"] = "failed"
                manifest["cleanup_attempts"] = 0
                manifest["cleanup_verified_absent"] = False
        else:
            cleanup_result = {
                "cleanup_status": "not_attempted",
                "attempts": 0,
                "verified_absent": False,
                "simulated": dry_run,
            }
            if manifest is not None:
                manifest["cleanup_status"] = "not_attempted"
                manifest["cleanup_attempts"] = 0
                manifest["cleanup_verified_absent"] = False

        if manifest is not None:
            manifest["original_exception"] = original_exception
            manifest["application_exception"] = application_exception
            manifest["browser_exception"] = browser_exception
            manifest["cleanup_exception"] = cleanup_exception
            manifest["state_write_exception"] = state_write_exception
            if rule_applied and cleanup_result["cleanup_status"] == "cleaned":
                if browser_exception is None:
                    manifest["final_status"] = "completed"
                else:
                    manifest["final_status"] = "browser_failed_cleanup_completed"
            elif rule_applied:
                manifest["final_status"] = "cleanup_failed"
            elif manifest.get("final_status") == "browser_completed":
                manifest["final_status"] = "completed"
            manifest["cleanup_persistence_status"] = "pending"
            try:
                manifest["cleanup_persistence_status"] = "persisted"
                sync_lifecycle_state(manifest)
            except BaseException as error:
                state_write_exception = f"{type(error).__name__}: {error}"
                manifest["state_write_exception"] = state_write_exception
                manifest["cleanup_persistence_status"] = "failed"
                if rule_applied and cleanup_result["cleanup_status"] == "cleaned":
                    cleanup_result["cleanup_status"] = "cleaned_unpersisted"
                    manifest["cleanup_status"] = "cleaned_unpersisted"
                    manifest["cleanup_verified_absent"] = True
                    manifest["final_status"] = "cleanup_verified_but_state_not_persisted"

    return {
        "dry_run": dry_run,
        "watchdog_pid": watchdog_pid,
        "browser_report": browser_report,
        "rule_applied": rule_applied,
        "cleanup": cleanup_result,
        "original_exception": original_exception,
        "application_exception": application_exception,
        "browser_exception": browser_exception,
        "cleanup_exception": cleanup_exception,
        "state_write_exception": state_write_exception,
        "manifest": manifest,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["ipv4_only", "ipv6_only"], required=True)
    parser.add_argument("--url", default="https://example.com")
    args = parser.parse_args()

    result = run_orchestration(
        args.mode,
        args.url,
        dry_run=True,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
