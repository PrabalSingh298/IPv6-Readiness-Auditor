<#
.SYNOPSIS
Removes only firewall rules tracked by the isolated firewall PoC.
.DESCRIPTION
This script loads state.json and removes DisplayName values recorded by
firewall_controller.py. It never removes rules outside that tracked list.
#>

$ErrorActionPreference = "Stop"
$StateFile = Join-Path $PSScriptRoot "state.json"

if (-not (Test-Path -LiteralPath $StateFile)) {
    Write-Output "No state.json file exists; no PoC firewall rules are tracked."
    exit 0
}

$State = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
foreach ($Rule in @($State.rules)) {
    $TrackedName = [string]$Rule.display_name
    $TrackedGroup = [string]$Rule.group

    if (-not $TrackedName.StartsWith("IPv6-Auditor-Experimental-")) {
        Write-Output "Skipped an unrecognized rule name: $TrackedName"
        continue
    }

    $Removed = Get-NetFirewallRule -DisplayName $TrackedName -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Group -eq $TrackedGroup
        }
    if ($Removed) {
        foreach ($Item in $Removed) {
            Remove-NetFirewallRule -Name $Item.Name
            Write-Output "Removed tracked rule: $($Rule.display_name)"
        }
    } else {
        Write-Output "Already absent: $($Rule.display_name)"
    }
}

Remove-Item -LiteralPath $StateFile -Force
