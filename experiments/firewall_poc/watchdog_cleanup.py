import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from firewall_state import (
    atomic_json,
    load_json,
    is_stale,
    classify_state_pair,
    POLICY_ACTIVE_BEFORE_EXPIRY,
    POLICY_NORMAL_EXPIRY_CLEANUP,
    POLICY_ALREADY_CLEANED,
    POLICY_STALE_RECOVERY,
    POLICY_MISSING_OR_INVALID,
    POLICY_CONFLICT,
    parse_utc,
    validate_canonical_state,
)

ACTIVE_LOG: Path | None = None


def is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def write_log(message: str, log_override: Path | None = None) -> None:
    log_path = log_override or ACTIVE_LOG or Path(__file__).resolve().with_name("watchdog.log")
    timestamp = datetime.now(timezone.utc).isoformat()
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"{timestamp} {message}\n")


def load_state(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as state_file:
            state = json.load(state_file)
    except (json.JSONDecodeError, OSError) as error:
        write_log(f"invalid primary state JSON: {error}")
        return None
    if not isinstance(state, dict):
        write_log("invalid primary state structure")
        return None
    errors = validate_canonical_state(state)
    if errors:
        write_log("invalid primary state: " + "; ".join(errors))
        return None
    return state


def reconstruct_state(primary: Path, recovery: Path) -> dict | None:
    if not recovery.is_file():
        write_log("missing recovery manifest; refusing cleanup")
        return None
    manifest = load_json(recovery)
    if manifest is None:
        write_log("corrupted recovery manifest; refusing cleanup")
        return None
    errors = validate_canonical_state(manifest)
    if errors:
        write_log("invalid recovery manifest: " + "; ".join(errors))
        return None
    if is_stale(manifest):
        write_log("recovery manifest is expired; preserving it for manual recovery")
        return None
    reconstructed = dict(manifest)
    reconstructed["recovery_source"] = "recovery_manifest"
    atomic_json(primary, reconstructed)
    write_log("reconstructed primary state from valid recovery manifest")
    return reconstructed


def main() -> int:
    global ACTIVE_LOG
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-file", required=True, type=Path)
    parser.add_argument("--expiry", required=True)
    parser.add_argument("--recovery-file", type=Path)
    parser.add_argument("--cleanup-helper")
    parser.add_argument("--test-mode", action="store_true")
    parser.add_argument("--log-file", type=Path)
    args = parser.parse_args()
    if args.log_file:
        ACTIVE_LOG = args.log_file

    try:
        expiry = parse_utc(args.expiry)
    except (AttributeError, TypeError, ValueError):
        write_log("invalid watchdog expiry; refusing cleanup")
        return 2

    if not args.test_mode and not is_administrator():
        write_log("watchdog lacks administrator privileges; refusing cleanup")
        return 4
    if args.test_mode and not args.cleanup_helper:
        write_log("test mode requires an isolated cleanup helper")
        return 2
    write_log("watchdog started")

    recovery = args.recovery_file
    if recovery is None:
        recovery = args.state_file.with_name("recovery_manifest.json")

    state = load_state(args.state_file)
    recovery_state = load_json(recovery)
    policy, selected = classify_state_pair(state, recovery_state)

    if policy == POLICY_ALREADY_CLEANED:
        write_log("primary state is already cleaned")
        return 0
    if policy == POLICY_CONFLICT:
        write_log("primary and recovery state conflict; cleanup refused")
        return 5
    if policy in (POLICY_STALE_RECOVERY, POLICY_MISSING_OR_INVALID):
        write_log("missing, invalid, or stale recovery state; cleanup refused")
        return 5

    if state is None:
        state = reconstruct_state(args.state_file, recovery)
        if state is None:
            write_log("both recovery sources unavailable; no cleanup attempted")
            return 5

    if state.get("cleanup_status") == "cleaned":
        write_log("primary state is already cleaned")
        return 0

    while datetime.now(timezone.utc) < expiry:
        state = load_state(args.state_file)
        if state is None:
            state = reconstruct_state(args.state_file, recovery)
            if state is None:
                write_log("state became unavailable; cleanup refused")
                return 5
        if state.get("cleanup_status") == "cleaned":
            write_log("cleanup completed normally")
            return 0
        time.sleep(1)

    state = load_state(args.state_file)
    if state is None:
        state = reconstruct_state(args.state_file, recovery)
    if state is None:
        write_log("no valid state at expiry; cleanup refused")
        return 5
    if state.get("cleanup_status") == "cleaned":
        write_log("already cleaned at expiry")
        return 0

    if args.test_mode:
        helper = Path(args.cleanup_helper)
        command = [
            sys.executable,
            str(helper),
            "--state-file",
            str(args.state_file),
            "--recovery-file",
            str(recovery),
        ]
    else:
        script = Path(__file__).resolve().with_name("cleanup_firewall_rules.ps1")
        command = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ]

    for attempt in (1, 2):
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            write_log(f"cleanup helper succeeded on attempt {attempt}")
            return 0
        if result.returncode == 6:
            write_log("cleanup removal verified but state persistence failed")
            return 6
        write_log(
            f"cleanup helper attempt {attempt} failed with exit "
            f"{result.returncode}: {result.stderr.strip()}"
        )
        if attempt == 1:
            time.sleep(1)
    write_log("cleanup failed after bounded retry")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
