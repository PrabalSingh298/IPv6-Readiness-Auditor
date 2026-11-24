import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = 1
POC_PREFIX = "IPv6-Auditor-Experimental-"
SUPPORTED_MODES = ("ipv4_only", "ipv6_only")
CLEANUP_STATUSES = (
    "pending",
    "active",
    "cleaned",
    "cleaned_unpersisted",
    "failed",
    "watchdog_failed",
    "not_attempted",
    "already_exists",
    "created_unverified",
    "exact_name_property_conflict",
)
WATCHDOG_STATUSES = ("pending", "running", "dry_run", "stopped", "failed")
APPLICATION_STATUSES = (
    "pending",
    "active",
    "created_unverified",
    "already_exists",
    "exact_name_property_conflict",
    "application_failed",
)
POLICY_ACTIVE_BEFORE_EXPIRY = "active_before_expiry"
POLICY_NORMAL_EXPIRY_CLEANUP = "normal_expiry_cleanup"
POLICY_ALREADY_CLEANED = "already_cleaned"
POLICY_STALE_RECOVERY = "stale_recovery"
POLICY_MISSING_OR_INVALID = "missing_or_invalid"
POLICY_CONFLICT = "conflicting_primary_and_recovery"
SAFE_INTERNAL_NAME = re.compile(r"[A-Za-z0-9_-]+")


def iso_utc(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def validate_safe_internal_name(value) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and SAFE_INTERNAL_NAME.fullmatch(value) is not None
    )


def validate_canonical_state(state) -> list[str]:
    if not isinstance(state, dict):
        return ["missing or malformed state"]

    required = (
        "schema_version", "experiment_id", "mode", "exact_rule_name",
        "display_name", "group", "executable_path", "remote_address",
        "direction", "action", "protocol", "creation_time", "expiry_time",
        "creation_status", "application_status", "cleanup_status",
        "cleanup_verified_absent", "cleanup_persistence_status",
        "final_status", "watchdog",
    )
    missing = [field for field in required if field not in state]
    if missing:
        return [f"missing field: {field}" for field in missing]

    if state["schema_version"] != SCHEMA_VERSION:
        return ["unsupported state schema_version"]
    if not isinstance(state["experiment_id"], str) or not state["experiment_id"]:
        return ["invalid experiment_id"]
    if state["mode"] not in SUPPORTED_MODES:
        return ["unsupported firewall mode"]
    for field in ("exact_rule_name", "display_name", "group"):
        if not isinstance(state[field], str) or not state[field].startswith(POC_PREFIX):
            return [f"unrecognized PoC prefix for {field}"]
    for field in ("exact_rule_name", "display_name", "group"):
        if not validate_safe_internal_name(state[field]):
            return [f"unsafe internal name characters in {field}"]
    if state["exact_rule_name"] != state["display_name"]:
        return ["internal rule name and display name do not match"]
    if not state["exact_rule_name"].startswith(state["group"]):
        return ["rule name is inconsistent with rule group"]
    if not isinstance(state["executable_path"], str) or not state["executable_path"]:
        return ["invalid executable_path"]
    if not os.path.isabs(state["executable_path"].replace("/", "\\")):
        return ["executable_path must be an absolute path"]
    if state["direction"] != "Outbound":
        return ["unsupported direction"]
    if state["action"] != "Block":
        return ["unsupported action"]
    if state["protocol"] != "Any":
        return ["unsupported protocol"]

    expected_address = "::/0" if state["mode"] == "ipv4_only" else "0.0.0.0/0"
    if state["remote_address"] != expected_address:
        return ["remote address does not match firewall mode"]
    if state["cleanup_status"] not in CLEANUP_STATUSES:
        return ["unsupported cleanup_status"]
    if state.get("creation_status") not in (
        "pending", "preserved", "created_unverified", "application_failed"
    ):
        return ["unsupported creation_status"]
    if state.get("application_status") not in APPLICATION_STATUSES:
        return ["unsupported application_status"]
    if not isinstance(state["cleanup_verified_absent"], bool):
        return ["cleanup_verified_absent must be a boolean"]
    if state["cleanup_persistence_status"] not in (
        "pending", "persisted", "failed", "not_required"
    ):
        return ["unsupported cleanup_persistence_status"]
    watchdog = state["watchdog"]
    if not isinstance(watchdog, dict):
        return ["invalid watchdog information"]
    watchdog_required = ("process_id", "started", "status")
    watchdog_missing = [field for field in watchdog_required if field not in watchdog]
    if watchdog_missing:
        return [f"missing watchdog field: {field}" for field in watchdog_missing]
    if not isinstance(watchdog["started"], bool):
        return ["watchdog.started must be a boolean"]
    if watchdog["status"] not in WATCHDOG_STATUSES:
        return ["unsupported watchdog status"]
    process_id = watchdog["process_id"]
    if process_id is not None:
        if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
            return ["invalid watchdog process_id"]
    if watchdog["status"] == "dry_run" and (
        watchdog["started"] or process_id is not None
    ):
        return ["inconsistent dry-run watchdog metadata"]
    if watchdog["status"] == "pending" and (
        watchdog["started"] or process_id is not None
    ):
        return ["inconsistent pending watchdog metadata"]
    if watchdog["status"] == "running" and (
        not watchdog["started"] or process_id is None
    ):
        return ["running watchdog requires started=true and process_id"]
    if watchdog["status"] in ("running", "stopped", "failed") and not watchdog["started"]:
        return ["watchdog status requires started=true"]

    try:
        created = parse_utc(state["creation_time"])
        expiry = parse_utc(state["expiry_time"])
    except (AttributeError, TypeError, ValueError):
        return ["invalid creation or expiry timestamp"]
    if expiry < created:
        return ["expiry_time precedes creation_time"]
    return []


def is_stale(state: dict, now: datetime | None = None) -> bool:
    errors = validate_canonical_state(state)
    if errors:
        return True
    expiry = parse_utc(state["expiry_time"])
    return expiry <= (now or datetime.now(timezone.utc))


IDENTITY_FIELDS = (
    "experiment_id",
    "mode",
    "exact_rule_name",
    "display_name",
    "group",
    "executable_path",
    "remote_address",
    "direction",
    "action",
    "protocol",
    "creation_time",
    "expiry_time",
)


def classify_state_pair(primary, recovery, now: datetime | None = None) -> tuple[str, dict | None]:
    now = now or datetime.now(timezone.utc)

    primary_errors = validate_canonical_state(primary) if isinstance(primary, dict) else ["missing or malformed state"]
    recovery_errors = validate_canonical_state(recovery) if isinstance(recovery, dict) else ["missing or malformed state"]

    if primary is not None and not primary_errors and recovery is not None and not recovery_errors:
        for field in IDENTITY_FIELDS:
            if primary.get(field) != recovery.get(field):
                return POLICY_CONFLICT, primary

    if primary is not None and not primary_errors:
        if primary.get("cleanup_status") == "cleaned":
            expiry = parse_utc(primary["expiry_time"])
            if expiry <= now:
                return POLICY_STALE_RECOVERY, primary
            return POLICY_ALREADY_CLEANED, primary
        expiry = parse_utc(primary["expiry_time"])
        if expiry <= now:
            return POLICY_NORMAL_EXPIRY_CLEANUP, primary
        return POLICY_ACTIVE_BEFORE_EXPIRY, primary

    if primary is None or primary_errors:
        if recovery is not None and not recovery_errors:
            if is_stale(recovery, now):
                return POLICY_STALE_RECOVERY, recovery
            return POLICY_ACTIVE_BEFORE_EXPIRY, recovery
        return POLICY_MISSING_OR_INVALID, recovery
