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
    Write-Error "REFUSED: missing state.json; no PoC firewall rule may be identified."
    exit 2
}

try {
    $State = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
} catch {
    Write-Error "REFUSED: state.json is missing or corrupted."
    exit 2
}

$RequiredFields = @(
    "schema_version", "experiment_id", "mode", "exact_rule_name",
    "display_name", "group", "executable_path", "remote_address",
    "direction", "action", "protocol", "creation_time", "expiry_time",
    "creation_status", "application_status", "cleanup_status",
    "cleanup_verified_absent", "cleanup_persistence_status",
    "final_status", "watchdog"
)
foreach ($Field in $RequiredFields) {
    if ($null -eq $State.PSObject.Properties[$Field]) {
        Write-Error "REFUSED: incomplete state file; missing $Field"
        exit 2
    }
}
if ([int]$State.schema_version -ne 1) {
    Write-Error "REFUSED: unsupported state schema."
    exit 2
}
if ([string]$State.exact_rule_name -notmatch '^IPv6-Auditor-Experimental-[A-Za-z0-9_-]+$') {
    Write-Error "REFUSED: unrecognized PoC rule name."
    exit 2
}
if ([string]$State.group -notmatch '^IPv6-Auditor-Experimental-[A-Za-z0-9_-]+$') {
    Write-Error "REFUSED: unrecognized PoC rule group."
    exit 2
}
if ([string]$State.executable_path -eq "") {
    Write-Error "REFUSED: executable path is missing."
    exit 2
}
if ($null -eq $State.watchdog -or
    $null -eq $State.watchdog.PSObject.Properties["process_id"] -or
    $null -eq $State.watchdog.PSObject.Properties["started"] -or
    $null -eq $State.watchdog.PSObject.Properties["status"]) {
    Write-Error "REFUSED: watchdog metadata is incomplete."
    exit 2
}
if ($State.watchdog.started -isnot [bool]) {
    Write-Error "REFUSED: watchdog.started must be a boolean."
    exit 2
}
if ([string]$State.watchdog.status -notin @("pending","running","dry_run","stopped","failed")) {
    Write-Error "REFUSED: watchdog status is unsupported."
    exit 2
}
if ($null -ne $State.watchdog.process_id) {
    if ($State.watchdog.process_id -isnot [int] -or [int]$State.watchdog.process_id -le 0) {
        Write-Error "REFUSED: watchdog process_id is invalid."
        exit 2
    }
}
if ([string]$State.watchdog.status -eq "dry_run" -and
    ($State.watchdog.started -or $null -ne $State.watchdog.process_id)) {
    Write-Error "REFUSED: dry-run watchdog metadata is inconsistent."
    exit 2
}
if ([string]$State.exact_rule_name -ne [string]$State.display_name) {
    Write-Error "REFUSED: internal rule name and display name mismatch."
    exit 2
}
if (-not [string]$State.exact_rule_name.StartsWith([string]$State.group)) {
    Write-Error "REFUSED: internal rule name is inconsistent with group."
    exit 2
}
if ([string]$State.display_name -ne [string]$State.exact_rule_name) {
    Write-Error "REFUSED: tracked display name mismatch."
    exit 2
}
if ([string]$State.direction -ne "Outbound") {
    Write-Error "REFUSED: tracked direction mismatch."
    exit 2
}
if ([string]$State.action -ne "Block") {
    Write-Error "REFUSED: tracked action mismatch."
    exit 2
}
if ([string]$State.protocol -ne "Any") {
    Write-Error "REFUSED: tracked protocol mismatch."
    exit 2
}
if ([string]$State.creation_status -notin @("pending","preserved","created_unverified","application_failed")) {
    Write-Error "REFUSED: unsupported creation_status."
    exit 2
}
if ([string]$State.application_status -notin @("pending","active","created_unverified","already_exists","exact_name_property_conflict","application_failed")) {
    Write-Error "REFUSED: unsupported application_status."
    exit 2
}
if ([string]$State.cleanup_persistence_status -notin @("pending","persisted","failed","not_required")) {
    Write-Error "REFUSED: unsupported cleanup_persistence_status."
    exit 2
}

try {
    $Expiry = [datetimeoffset]::Parse([string]$State.expiry_time).UtcDateTime
} catch {
    Write-Error "REFUSED: expiry_time is invalid."
    exit 2
}
if ([string]$State.creation_time -notmatch '(Z|z|[+-]\d{2}:\d{2})$' -or
    [string]$State.expiry_time -notmatch '(Z|z|[+-]\d{2}:\d{2})$') {
    Write-Error "REFUSED: timestamps must include an ISO 8601 timezone."
    exit 2
}
try {
    $Created = [datetimeoffset]::Parse([string]$State.creation_time).UtcDateTime
} catch {
    Write-Error "REFUSED: creation_time is invalid."
    exit 2
}
if ($Expiry -lt $Created) {
    Write-Error "REFUSED: expiry_time precedes creation_time."
    exit 2
}
if ($Expiry -lt [datetime]::UtcNow) {
    if ([string]$State.cleanup_status -eq "cleaned") {
        Write-Error "REFUSED: stale cleaned state is preserved for manual recovery; expiry $($State.expiry_time)"
        exit 4
    }
    Write-Output "Normal expiry cleanup eligible: $($State.experiment_id); expiry $($State.expiry_time)"
}

$TrackedInternalName = [string]$State.exact_rule_name
$TrackedName = [string]$State.display_name
$TrackedGroup = [string]$State.group
$TrackedProgram = [string]$State.executable_path
if ($State.mode -eq "ipv4_only" -and [string]$State.remote_address -ne "::/0") {
    Write-Error "REFUSED: IPv4-only remote address mismatch."
    exit 2
}
if ($State.mode -eq "ipv6_only" -and [string]$State.remote_address -ne "0.0.0.0/0") {
    Write-Error "REFUSED: IPv6-only remote address mismatch."
    exit 2
}
if ($State.mode -ne "ipv4_only" -and $State.mode -ne "ipv6_only") {
    Write-Error "REFUSED: unsupported firewall mode."
    exit 2
}

if ([string]$State.cleanup_status -eq "cleaned") {
    $Remaining = Get-NetFirewallRule -Name ([string]$State.exact_rule_name) -ErrorAction SilentlyContinue
    if ($Remaining) {
        Write-Error "REFUSED: state says cleaned but the exact rule remains; manual verification required."
        exit 3
    }
    Write-Output "Already cleaned: no removal attempted."
    exit 0
}

if (-not $TrackedName.StartsWith("IPv6-Auditor-Experimental-")) {
    Write-Error "REFUSED: unrecognized PoC rule name: $TrackedName"
    exit 2
}
if (-not $TrackedGroup.StartsWith("IPv6-Auditor-Experimental-")) {
    Write-Error "REFUSED: unrecognized PoC rule group: $TrackedGroup"
    exit 2
}

$ExactMatches = @(Get-NetFirewallRule -Name $TrackedInternalName -ErrorAction SilentlyContinue)
if ($ExactMatches.Count -gt 1) {
    Write-Error "REFUSED: multiple firewall rules have the exact tracked internal Name."
    exit 2
}
$Matches = @($ExactMatches | Where-Object {
        $_.DisplayName -eq $TrackedName -and
        $_.Group -eq $TrackedGroup -and
        [string]$_.Direction -eq [string]$State.direction -and
        [string]$_.Action -eq [string]$State.action -and
        [string]$_.Protocol -eq [string]$State.protocol
    })
if ($ExactMatches.Count -eq 1 -and $Matches.Count -ne 1) {
    $State.cleanup_status = "exact_name_property_conflict"
    $State.application_status = "exact_name_property_conflict"
    Write-Error "REFUSED: exact tracked rule identity or properties do not match."
    exit 2
}
if ($Matches) {
    $Application = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Matches |
        Select-Object -First 1
    $Address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Matches |
        Select-Object -First 1
    if ([string]$Application.Program -ne $TrackedProgram -or
        [string]$Address.RemoteAddresses -ne [string]$State.remote_address) {
        Write-Error "REFUSED: exact tracked rule properties do not match."
        exit 2
    }
    foreach ($Item in @($Matches)) {
        Remove-NetFirewallRule -Name $Item.Name -ErrorAction Stop
    }
}

$Remaining = Get-NetFirewallRule -Name $TrackedInternalName -ErrorAction SilentlyContinue
if ($Remaining) {
    $State.cleanup_status = "failed"
    $State.cleanup_verified_absent = $false
    $State.final_status = "rule_still_present"
    Write-Error "FAILED: exact tracked rule remains after removal attempt."
    exit 3
}
Write-Output "Verified absent: $TrackedName ($TrackedInternalName)"

$State.cleanup_status = "cleaned"
$State.cleanup_verified_absent = $true
$State.final_status = "cleaned"
$State | Add-Member -NotePropertyName cleanup_time -NotePropertyValue (
    [datetime]::UtcNow.ToString("o")
) -Force
try {
    $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StateFile -Encoding UTF8 -ErrorAction Stop
    $Reloaded = Get-Content -LiteralPath $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ([string]$Reloaded.cleanup_status -ne "cleaned") {
        throw "persisted cleanup_status did not verify"
    }
    $State.cleanup_persistence_status = "persisted"
    $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StateFile -Encoding UTF8 -ErrorAction Stop
} catch {
    $State.cleanup_status = "cleaned_unpersisted"
    $State.cleanup_verified_absent = $true
    $State.cleanup_persistence_status = "failed"
    $State.final_status = "cleanup_verified_but_state_not_persisted"
    Write-Error "REMOVAL_VERIFIED_BUT_STATE_PERSISTENCE_FAILED: $($_.Exception.Message)"
    exit 6
}
