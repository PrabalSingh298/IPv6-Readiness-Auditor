import argparse
import ctypes
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright
from firewall_state import (
    SCHEMA_VERSION,
    atomic_json,
    iso_utc,
    is_stale,
    validate_canonical_state,
)


EXPERIMENT_DIRECTORY = Path(__file__).resolve().parent
STATE_FILE = EXPERIMENT_DIRECTORY / "state.json"
GROUP_NAME = f"IPv6-Auditor-Experimental-{uuid.uuid4().hex[:12]}"
VERIFIED_HEADLESS_SHELL_PATH = (
    Path.home()
    / "AppData"
    / "Local"
    / "ms-playwright"
    / "chromium_headless_shell-1255"
    / "chrome-headless-shell-win64"
    / "chrome-headless-shell.exe"
)


def is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def chromium_executable() -> str:
    with sync_playwright() as playwright:
        return str(playwright.chromium.executable_path)


def headless_shell_executable(configured_path: str | None = None) -> str:
    if configured_path:
        return str(Path(configured_path).expanduser())

    try:
        main_executable = Path(chromium_executable())
        ms_playwright_directory = main_executable.parents[2]
        chromium_directory_name = main_executable.parents[1].name
        build_suffix = chromium_directory_name.removeprefix("chromium-")
        candidate = (
            ms_playwright_directory
            / f"chromium_headless_shell-{build_suffix}"
            / "chrome-headless-shell-win64"
            / "chrome-headless-shell.exe"
        )
        if candidate.exists():
            return str(candidate)
    except (IndexError, OSError):
        pass

    return str(VERIFIED_HEADLESS_SHELL_PATH)


def validate_executable(executable: str) -> None:
    path = Path(executable).expanduser()
    if not path.is_file():
        raise FileNotFoundError(
            f"Configured Chromium NetworkService executable not found: {path}"
        )


def proposed_rule(mode: str, executable: str) -> dict:
    if mode == "ipv4_only":
        return {
            "exact_rule_name": f"{GROUP_NAME}-Block-IPv6",
            "display_name": f"{GROUP_NAME}-Block-IPv6",
            "group": GROUP_NAME,
            "remote_address": "::/0",
            "action": "Block",
            "direction": "Outbound",
            "protocol": "Any",
            "program": executable,
            "mode": mode,
        }
    if mode == "ipv6_only":
        return {
            "exact_rule_name": f"{GROUP_NAME}-Block-IPv4",
            "display_name": f"{GROUP_NAME}-Block-IPv4",
            "group": GROUP_NAME,
            "remote_address": "0.0.0.0/0",
            "action": "Block",
            "direction": "Outbound",
            "protocol": "Any",
            "program": executable,
            "mode": mode,
        }
    raise ValueError("Mode must be ipv4_only or ipv6_only")


def powershell_rule_command(rule: dict) -> str:
    def quoted(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    return (
        "New-NetFirewallRule "
        f"-Name {quoted(rule['exact_rule_name'])} "
        f"-DisplayName {quoted(rule['display_name'])} "
        f"-Group {quoted(rule['group'])} "
        "-Direction Outbound "
        "-Action Block "
        "-Protocol Any "
        f"-Program {quoted(rule['program'])} "
        f"-RemoteAddress {quoted(rule['remote_address'])} "
        "-Enabled True "
        "-Profile Any"
    )


def load_tracked_rules() -> list[dict]:
    if not STATE_FILE.exists():
        return []
    with STATE_FILE.open("r", encoding="utf-8") as state_file:
        data = json.load(state_file)
    return data.get("rules", [])

def save_tracked_rules(rules: list[dict]) -> None:
    state = rules if isinstance(rules, dict) else None
    if state is None:
        state = {"rules": rules}
    atomic_json(STATE_FILE, state)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def build_experiment_state(
    mode: str,
    rule: dict,
    duration_seconds: int = 900,
) -> dict:
    created = utc_now()
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
        "cleanup_status": "pending",
        "watchdog": {
            "process_id": None,
            "started": False,
            "status": "pending",
        },
    }


def validate_experiment_state(state: dict) -> list[str]:
    return validate_canonical_state(state)


def is_stale_state(state: dict, now: datetime | None = None) -> bool:
    if validate_experiment_state(state):
        return True
    expiry = datetime.fromisoformat(state["expiry_time"].replace("Z", "+00:00"))
    return expiry <= (now or utc_now())


def repeated_cleanup_status(state: dict) -> bool:
    return state.get("cleanup_status") == "cleaned"


def apply_rule(rule: dict) -> None:
    raise RuntimeError("Real firewall application is disabled in this PoC")


def launch_watchdog(state: dict) -> int | None:
    """Launch an independent, elevated-by-inheritance process with a hard timeout."""
    script = EXPERIMENT_DIRECTORY / "watchdog_cleanup.py"
    try:
        if os.name == "nt":
            creation_flags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "DETACHED_PROCESS", 0)
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(script),
                    "--state-file",
                    str(STATE_FILE),
                    "--expiry",
                    state["expiry_time"],
                    "--recovery-file",
                    str(EXPERIMENT_DIRECTORY / "recovery_manifest.json"),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(EXPERIMENT_DIRECTORY),
                creationflags=creation_flags,
                close_fds=True,
            )
        else:
            process = subprocess.Popen(
                [sys.executable, str(script), "--state-file", str(STATE_FILE)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(EXPERIMENT_DIRECTORY),
                start_new_session=True,
                close_fds=True,
            )
        return process.pid
    except OSError as error:
        print(f"REFUSED: watchdog could not start: {error}")
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["ipv4_only", "ipv6_only"], required=True)
    parser.add_argument(
        "--executable",
        help="Optional headless-shell executable path for a future Playwright build",
    )
    args = parser.parse_args()

    executable = headless_shell_executable(args.executable)
    try:
        validate_executable(executable)
    except FileNotFoundError as error:
        print(f"REFUSED: {error}")
        return 2

    rule = proposed_rule(args.mode, executable)
    command = powershell_rule_command(rule)
    actual_main_executable = chromium_executable()
    executable_matches_actual_network_owner = (
        Path(executable).name == "chrome-headless-shell.exe"
        and executable.lower().find("chromium_headless_shell-") != -1
    )

    print("Requested mode:", args.mode)
    print("Network executable:", executable)
    print("Playwright main Chromium executable:", actual_main_executable)
    print(
        "Network executable match:",
        "headless-shell name confirmed"
        if executable_matches_actual_network_owner
        else "unverified",
    )
    print("Unique rule group:", rule["group"])
    print("Address range blocked:", rule["remote_address"])
    print("PowerShell command:")
    print(command)

    print("DRY-RUN: no firewall rule was created.")
    print("Real firewall application is disabled; no application option is available.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
