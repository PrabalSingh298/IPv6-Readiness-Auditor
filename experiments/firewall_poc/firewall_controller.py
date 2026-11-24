import argparse
import ctypes
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from playwright.sync_api import sync_playwright


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
    with STATE_FILE.open("w", encoding="utf-8") as state_file:
        json.dump({"rules": rules}, state_file, indent=2)


def apply_rule(rule: dict) -> None:
    if not is_administrator():
        raise PermissionError("Administrator privileges are required")

    command = powershell_rule_command(rule)
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Firewall rule creation failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["ipv4_only", "ipv6_only"], required=True)
    parser.add_argument("--apply-firewall-rules", action="store_true")
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

    if not args.apply_firewall_rules:
        print("DRY-RUN: no firewall rule was created.")
        return 0

    if not is_administrator():
        print("REFUSED: the current session is not administrator.")
        return 3

    existing = load_tracked_rules()
    try:
        apply_rule(rule)
        existing.append(rule)
        save_tracked_rules(existing)
    except Exception as error:
        print(f"REFUSED OR FAILED: {type(error).__name__}: {error}")
        return 4

    print("APPLIED: rule was created. Track state in:", STATE_FILE)
    print("Run cleanup_firewall_rules.ps1 after the experiment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
