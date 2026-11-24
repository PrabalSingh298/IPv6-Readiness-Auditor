import json
import os
import subprocess
from dataclasses import dataclass
from typing import Callable

from firewall_state import validate_safe_internal_name


class FirewallAdapterError(RuntimeError):
    pass


class ExistingRuleError(FirewallAdapterError):
    pass


class CreatedUnverifiedError(FirewallAdapterError):
    pass


class ExactNamePropertyConflictError(FirewallAdapterError):
    pass


@dataclass
class PowerShellResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class PowerShellRunner:
    def run(self, script: str, timeout: int, env: dict[str, str]) -> PowerShellResult:
        raise NotImplementedError


class SubprocessPowerShellRunner(PowerShellRunner):
    def __init__(self, executable: str = "powershell.exe"):
        self.executable = executable

    def run(self, script: str, timeout: int, env: dict[str, str]) -> PowerShellResult:
        runner_env = dict(os.environ)
        runner_env.update(env)
        try:
            result = subprocess.run(
                [
                    self.executable,
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "-",
                ],
                input=script,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                env=runner_env,
            )
            return PowerShellResult(result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired as error:
            raise FirewallAdapterError(
                f"PowerShell timed out after {timeout} seconds"
            ) from error
        except OSError as error:
            raise FirewallAdapterError(f"PowerShell could not start: {error}") from error


class MockFirewallAdapter:
    def __init__(self, rules=None, removal_fails=False, remain_after_remove=False):
        self.rules = {rule["name"]: dict(rule) for rule in (rules or [])}
        self.removal_fails = removal_fails
        self.remain_after_remove = remain_after_remove
        self.remove_attempts = 0
        self.apply_attempts = 0

    def apply_exact(self, rule):
        self.apply_attempts += 1
        name = rule["exact_rule_name"]
        if not validate_safe_internal_name(name):
            raise FirewallAdapterError("Unsafe or wildcard internal rule Name")
        if name in self.rules:
            found = self.rules[name]
            if not self.matches_properties(found, rule):
                raise ExactNamePropertyConflictError(
                    "EXACT_NAME_PROPERTY_CONFLICT: exact Name exists with different properties"
                )
            raise ExistingRuleError(
                "ALREADY_EXISTS: exact internal firewall rule Name already exists"
            )
        found = {
            "name": rule["exact_rule_name"],
            "display_name": rule["display_name"],
            "group": rule["group"],
            "program": rule["executable_path"],
            "remote_address": rule["remote_address"],
            "direction": rule["direction"],
            "action": rule["action"],
            "protocol": rule["protocol"],
        }
        self.rules[rule["exact_rule_name"]] = found
        return found

    def find_exact(self, rule):
        if not validate_safe_internal_name(rule.get("exact_rule_name")):
            raise FirewallAdapterError("Unsafe or wildcard internal rule Name")
        found = self.rules.get(rule["exact_rule_name"])
        if not found:
            for candidate in self.rules.values():
                if (
                    candidate.get("display_name") == rule["display_name"]
                    and candidate.get("group") == rule["group"]
                    and candidate.get("program") == rule["executable_path"]
                ):
                    return "MISMATCH"
            return None
        if not self.matches_properties(found, rule):
            raise ExactNamePropertyConflictError(
                "EXACT_NAME_PROPERTY_CONFLICT: exact Name exists with different properties"
            )
        return found

    @staticmethod
    def matches_properties(found, rule):
        expected = {
            "name": rule["exact_rule_name"],
            "display_name": rule["display_name"],
            "group": rule["group"],
            "program": rule["executable_path"],
            "remote_address": rule["remote_address"],
            "direction": rule["direction"],
            "action": rule["action"],
            "protocol": rule["protocol"],
        }
        return all(found.get(key) == value for key, value in expected.items())

    def remove_exact(self, rule):
        self.remove_attempts += 1
        if self.removal_fails:
            return False
        try:
            found = self.find_exact(rule)
        except ExactNamePropertyConflictError:
            raise
        if found is None or found in ("MISMATCH", "EXACT_NAME_PROPERTY_CONFLICT"):
            return False
        if not self.remain_after_remove:
            self.rules.pop(rule["exact_rule_name"], None)
        return True

    def verify_absent(self, rule):
        return self.find_exact(rule) is None


class WindowsFirewallAdapter:
    def __init__(self, runner: PowerShellRunner | None = None, timeout: int = 30):
        self.runner = runner or SubprocessPowerShellRunner()
        self.timeout = timeout

    @staticmethod
    def _rule_env(rule: dict) -> dict[str, str]:
        env = {
            "POC_RULE_NAME": str(rule["exact_rule_name"]),
            "POC_DISPLAY_NAME": str(rule["display_name"]),
            "POC_GROUP": str(rule["group"]),
            "POC_PROGRAM": str(rule["executable_path"]),
            "POC_REMOTE_ADDRESS": str(rule["remote_address"]),
            "POC_DIRECTION": str(rule["direction"]),
            "POC_ACTION": str(rule["action"]),
            "POC_PROTOCOL": str(rule["protocol"]),
        }
        for key, value in env.items():
            if "\x00" in value or any(ord(character) < 32 and character not in "\t" for character in value):
                raise FirewallAdapterError(f"Unsafe PowerShell environment value: {key}")
        return env

    FIND_SCRIPT = r"""
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$name = [string]$env:POC_RULE_NAME
$rules = @(
    Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
)
$items = @()
foreach ($rule in $rules) {
    $application = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue) | Select-Object -First 1
    $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue) | Select-Object -First 1
    $items += [pscustomobject]@{
        name = [string]$rule.Name
        display_name = [string]$rule.DisplayName
        group = [string]$rule.Group
        program = [string]$application.Program
        remote_address = [string]$address.RemoteAddresses
        remote_addresses = @([string[]]$address.RemoteAddresses)
        direction = [string]$rule.Direction
        action = [string]$rule.Action
        protocol = [string]$rule.Protocol
    }
}
[pscustomobject]@{
    count = $rules.Count
    rules = @($items)
} | ConvertTo-Json -Compress -Depth 4
"""

    APPLY_SCRIPT = r"""
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
New-NetFirewallRule `
    -Name ([string]$env:POC_RULE_NAME) `
    -DisplayName ([string]$env:POC_DISPLAY_NAME) `
    -Group ([string]$env:POC_GROUP) `
    -Direction ([string]$env:POC_DIRECTION) `
    -Action ([string]$env:POC_ACTION) `
    -Protocol ([string]$env:POC_PROTOCOL) `
    -Program ([string]$env:POC_PROGRAM) `
    -RemoteAddress ([string]$env:POC_REMOTE_ADDRESS) `
    -Enabled True `
    -Profile Any
"""

    REMOVE_SCRIPT = r"""
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
Remove-NetFirewallRule -Name ([string]$env:POC_RULE_NAME) -ErrorAction Stop
"""

    def find_exact(self, rule):
        if not validate_safe_internal_name(rule.get("exact_rule_name")):
            raise FirewallAdapterError("Unsafe or wildcard internal rule Name")
        env = self._rule_env(rule)
        payload = self._query(self.FIND_SCRIPT, env)
        count = payload.get("count")
        rules = payload.get("rules")
        if not isinstance(count, int) or isinstance(count, bool):
            raise FirewallAdapterError("Firewall query omitted a valid count")
        if not isinstance(rules, list):
            raise FirewallAdapterError("Firewall query omitted a valid rules array")
        if count != len(rules):
            raise FirewallAdapterError("Firewall query count does not match returned rules")
        if count == 0:
            return None
        if count > 1:
            raise FirewallAdapterError("Duplicate exact-name firewall rules found")
        found = rules[0]
        if not isinstance(found, dict):
            raise FirewallAdapterError("Firewall rule result is not an object")
        required = (
            "name", "display_name", "group", "program", "remote_address",
            "direction", "action", "protocol",
        )
        missing = [field for field in required if field not in found]
        if missing:
            raise FirewallAdapterError(
                "Firewall rule result missing properties: " + ", ".join(missing)
            )
        if found["name"] != rule["exact_rule_name"]:
            raise FirewallAdapterError("Firewall query returned the wrong rule identity")
        if "remote_addresses" in found:
            remote_addresses = found["remote_addresses"]
            if isinstance(remote_addresses, list):
                if len(remote_addresses) != 1 or remote_addresses[0] != rule["remote_address"]:
                    raise FirewallAdapterError("Firewall rule has ambiguous remote address values")
            elif remote_addresses != rule["remote_address"]:
                raise FirewallAdapterError("Firewall rule remote address does not match")
        if not self.matches_properties(found, rule):
            raise ExactNamePropertyConflictError(
                "EXACT_NAME_PROPERTY_CONFLICT: exact Name exists with different properties"
            )
        return found

    def matches_properties(self, found, rule):
        if found is None:
            return False
        if isinstance(found, str):
            return False
        expected = {
            "name": "exact_rule_name",
            "display_name": "display_name",
            "group": "group",
            "remote_address": "remote_address",
            "direction": "direction",
            "action": "action",
            "protocol": "protocol",
            "program": "executable_path",
        }
        if not all(found.get(output_key) == rule[state_key]
                   for output_key, state_key in expected.items()):
            return False
        remote_addresses = found.get("remote_addresses")
        if remote_addresses is not None:
            if isinstance(remote_addresses, list):
                return len(remote_addresses) == 1 and remote_addresses[0] == rule["remote_address"]
            return remote_addresses == rule["remote_address"]
        return True

    def apply_exact(self, rule):
        found = self.find_exact(rule)
        if found is not None:
            raise ExistingRuleError(
                "ALREADY_EXISTS: exact internal firewall rule Name already exists"
            )
        env = self._rule_env(rule)
        result = self.runner.run(self.APPLY_SCRIPT, self.timeout, env)
        if result.returncode != 0:
            raise FirewallAdapterError(
                result.stderr.strip() or "Firewall rule creation failed"
            )
        try:
            verified = self.find_exact(rule)
        except (FirewallAdapterError, KeyError, ValueError) as error:
            raise CreatedUnverifiedError(
                f"CREATED_UNVERIFIED: creation returned success but verification failed: {error}"
            ) from error
        if verified is None:
            raise CreatedUnverifiedError(
                "CREATED_UNVERIFIED: creation returned success but exact rule was not found"
            )
        return verified

    def remove_exact(self, rule):
        found = self.find_exact(rule)
        if found is None:
            return True
        env = self._rule_env(rule)
        result = self.runner.run(self.REMOVE_SCRIPT, self.timeout, env)
        if result.returncode != 0:
            raise FirewallAdapterError(result.stderr.strip() or "Removal failed")
        if not self.verify_absent(rule):
            raise FirewallAdapterError(
                "Firewall rule remains present after removal attempt"
            )
        return True

    def verify_absent(self, rule):
        return self.find_exact(rule) is None

    def _query(self, script: str, env: dict[str, str]) -> dict:
        result = self.runner.run(script, self.timeout, env)
        if result.returncode != 0:
            raise FirewallAdapterError(result.stderr.strip() or "Firewall query failed")
        text = result.stdout.strip()
        if not text:
            raise FirewallAdapterError("Firewall query returned empty output")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise FirewallAdapterError(f"Invalid firewall query response: {error}")
        if not isinstance(payload, dict):
            raise FirewallAdapterError("Firewall query did not return a JSON object")
        return payload
