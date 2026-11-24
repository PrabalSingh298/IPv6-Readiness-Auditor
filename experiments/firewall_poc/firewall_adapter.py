import json
import subprocess
from pathlib import Path


class FirewallAdapterError(RuntimeError):
    pass


class MockFirewallAdapter:
    def __init__(self, rules=None, removal_fails=False, remain_after_remove=False):
        self.rules = {rule["name"]: dict(rule) for rule in (rules or [])}
        self.removal_fails = removal_fails
        self.remain_after_remove = remain_after_remove
        self.remove_attempts = 0
        self.apply_attempts = 0

    def apply_exact(self, rule):
        self.apply_attempts += 1
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
            return "MISMATCH"
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
        found = self.find_exact(rule)
        if found is None or found == "MISMATCH":
            return False
        if not self.remain_after_remove:
            self.rules.pop(rule["exact_rule_name"], None)
        return True

    def verify_absent(self, rule):
        return self.find_exact(rule) is None


class WindowsFirewallAdapter:
    @staticmethod
    def ps_quote(value):
        return "'" + str(value).replace("'", "''") + "'"

    def find_exact(self, rule):
        script = (
            "$ErrorActionPreference='Stop'; "
            "$r=Get-NetFirewallRule -Name " + self.ps_quote(rule["exact_rule_name"]) + " "
            "-ErrorAction SilentlyContinue | Select-Object -First 1; "
            "if ($null -eq $r) { Write-Output '[]'; exit 0 }; "
            "$a=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue; "
            "$p=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{name=$r.Name;display_name=$r.DisplayName;group=$r.Group;"
            "direction=[string]$r.Direction;action=[string]$r.Action;protocol=[string]$r.Protocol;"
            "remote_address=[string]$a.RemoteAddresses;program=[string]$p.Program} "
            "| ConvertTo-Json -Compress"
        )
        return self._query(script)

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
        return all(found.get(output_key) == rule[state_key]
                   for output_key, state_key in expected.items())

    def remove_exact(self, rule):
        script = (
            "$ErrorActionPreference='Stop'; "
            "Remove-NetFirewallRule -Name " + self.ps_quote(rule["exact_rule_name"]) + " "
            "-ErrorAction Stop"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode != 0:
            raise FirewallAdapterError(result.stderr.strip() or "Removal failed")
        return True

    def verify_absent(self, rule):
        return self.find_exact(rule) is None

    def _query(self, script):
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode != 0:
            raise FirewallAdapterError(result.stderr.strip() or "Firewall query failed")
        text = result.stdout.strip()
        if not text or text == "[]":
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            raise FirewallAdapterError(f"Invalid firewall query response: {error}")
