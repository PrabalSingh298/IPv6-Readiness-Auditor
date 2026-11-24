# Evidence-Based Windows Firewall Enforcement Test Plan

Status: prepared for explicit approval. No firewall rule is applied by this plan.

## A. Test destinations

### Dual-stack: `example.com`

Configured resolver evidence:

- A: `172.66.147.243`, `104.20.23.154`
- AAAA: `2606:4700:91b5:72db:f23b:4e5:ef6b:ff98`

Independent connectivity:

- `curl.exe -4 -I https://example.com`: HTTP 200
- `curl.exe -6 -I https://example.com`: HTTP 200

Classification: verified dual-stack.

### IPv4-only: `ipv4.google.com`

DNS evidence:

- CNAME: `ipv4.google.com`
- CNAME target: `ipv4.l.google.com`
- A: `172.217.24.110`
- AAAA: no address returned

Independent connectivity:

- `curl.exe -4 -I https://ipv4.google.com`: HTTP 200
- `curl.exe -6 -I https://ipv4.google.com`: `Could not resolve host`

Classification: verified IPv4-only for this test point at the time of
investigation. DNS or origin behavior can change, so repeat the A/AAAA checks
before applying a rule.

### IPv6-only: `ipv6.google.com`

DNS evidence:

- CNAME: `ipv6.google.com`
- CNAME target: `ipv6.l.google.com`
- A: no address returned
- AAAA: `2404:6800:4007:81b::200e`

Independent connectivity:

- `curl.exe -4 -I https://ipv6.google.com`: `Could not resolve host`
- `curl.exe -6 -I https://ipv6.google.com`: HTTP 200

Classification: verified IPv6-only for this test point at the time of
investigation. Repeat the DNS checks before applying a rule.

The configured DNS resolver evidence was captured on the active hotspot:

- IPv4 DNS: `10.48.162.49`
- IPv6 DNS: `2401:4900:b370:5b25::6e`

NAT64/DNS64 remains unknown. A successful IPv6-only browser connection must not
automatically be described as native IPv6.

## B. Test matrix

All browser tests use:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py `
  --mode <mode> `
  --url <url> `
  --disable-quic `
  --output experiments\firewall_poc\<report-name>.json
```

HTTP/3 is disabled for the first enforcement experiment to use a simpler TCP
baseline. That is an investigation setting, not proof of enforcement.

| Test | Destination | Mode | Expected navigation | Expected remote family | Verification |
|---|---|---|---|---|---|
| B1 | `example.com` | unrestricted | 200 or resource responses | Any observed family | Baseline remote peer and resource evidence |
| B2 | `ipv4.google.com` | unrestricted | 200 | IPv4 | Baseline IPv4 server address |
| B3 | `ipv6.google.com` | unrestricted | 200 | IPv6 | Baseline IPv6 server address |
| B4 | `example.com` | ipv4_only | 200 | IPv4 only | Every observed successful peer is IPv4; no observed IPv6 |
| B5 | `ipv4.google.com` | ipv4_only | 200 | IPv4 | IPv4 `server_addr()` peer observed |
| B6 | `ipv6.google.com` | ipv4_only | Navigation/IPv6 resolution failure | No successful IPv6 peer | Failed request or name-resolution evidence |
| B7 | `example.com` | ipv6_only | 200 only if native IPv6 or unknown translation permits it | IPv6 only | Every observed successful peer is IPv6 |
| B8 | `ipv4.google.com` | ipv6_only | Failure if no DNS64/NAT64 or 464XLAT path | No IPv4 peer should be observed directly | Mark success inconclusive if only a synthesized/translated peer is observed |
| B9 | `ipv6.google.com` | ipv6_only | 200 | IPv6 | IPv6 `server_addr()` peer observed |

Verification rules:

- Successful responses are verified only from Playwright `Response.server_addr()`.
- An IPv4-only result requires at least one observed IPv4 peer and no observed
  successful IPv6 peer.
- An IPv6-only result requires at least one observed IPv6 peer and no observed
  successful IPv4 peer.
- Missing peer observations are inconclusive.
- HTTP 200 or browser navigation alone is not proof of address-family enforcement.
- Request failures must preserve Playwright error text and count missing peers as
  unknown, not as a verified block.
- NAT64/DNS64 or 464XLAT can make a translated IPv6 address appear in
  `server_addr()`. That is evidence of a route, not native IPv6 reachability.

## C. Enforcement and cleanup safety

### Existing controller

- Dry-run is the default.
- Real rule application is disabled.
- Administrator privileges are checked but not granted.
- The default executable is:
  `C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe`
- The executable file must exist before rule preview or application.
- The controller supports `--executable` for a future Playwright build.
- It displays both the network executable and the main Chromium executable.

### Rule scope

- IPv4-only: block `::/0`, outbound, `-Protocol Any`.
- IPv6-only: block `0.0.0.0/0`, outbound, `-Protocol Any`.
- Unique display names use `IPv6-Auditor-Experimental-`.
- The unique group uses the same prefix.
- The rule targets only the configured headless-shell executable.

This scope does not identify or block all possible Chromium executable paths.
Any future run in normal headed mode or a changed Playwright executable layout
must repeat process-ownership investigation before use.

### State and cleanup

- Before application, the controller atomically saves
  `experiments/firewall_poc/state.json` with the experiment ID, mode, exact
  display name, group, executable path, creation time, expiry time, cleanup
  status, and rule fields.
- The same elevated Python process starts an independent watchdog process that
  waits until expiry and then invokes the local cleanup script. This covers
  browser failure and normal `try/finally` cleanup, and provides a strict
  timeout for Playwright/Python/terminal failures while Windows remains running.
- A watchdog process does not survive Windows restart. It cannot, by itself,
  protect against computer restart. The cleanup script plus stale state should
  be run after restart; no Task Scheduler recovery mechanism is needed for the
  dry-run/PoC design and no scheduled task is created.
- Cleanup accepts only an exact display name/group/executable triple recorded in
  a complete state file. The display name must begin
  `IPv6-Auditor-Experimental-`. It never removes an unrelated rule.
- A stale state is reported but can still be cleaned because it is the exact
  experiment record. Missing, malformed, mismatched, or incomplete state refuses
  cleanup. Repeated cleanup is idempotent and records `cleanup_status=cleaned`.
- Normal completion uses `try/finally` in the approved orchestration; the
  watchdog is the independent upper bound. If the watchdog cannot start, no
  firewall rule is applied.
- The experimental orchestration entry point is
  `firewall_orchestrator.py`. It is dry-run by default and has no real
  firewall application path in this implementation.
- The primary state file and secondary `recovery_manifest.json` record the exact
  Windows Firewall rule `Name`, display name, group, executable, address range,
  direction, action, protocol, experiment timing, watchdog PID, and status.
  Windows Firewall has no assumed GUID; `Name` is the exact internal identity.
- The recovery manifest may reconstruct only a missing or malformed primary
  state. Missing or corrupted state plus missing/corrupted recovery metadata
  refuses cleanup and never performs broad deletion.

### Canonical state and implementation status

`state.json` and `recovery_manifest.json` use the same canonical top-level
fields: experiment ID, mode, exact rule `Name`, display name, group, executable
path, remote address, direction, action, protocol, creation time, expiry time,
cleanup status, and watchdog status. Cleanup does not infer a separate nested
rule structure.

The orchestrator is dry-run by default. It has no real firewall application
option in the current PoC, and the `WindowsFirewallAdapter` is not enabled.
The mock adapter is used for orchestration and recovery tests. The Windows
adapter is implemented with an injectable runner, exact-name queries,
property verification, and post-removal absence checks, but it remains
execution-disabled and untested against real Windows Firewall.

The canonical timestamps must include a timezone. Expiry must be later than
creation. Recovery manifests are stale and refused for automatic cleanup after
expiry. If the primary state is missing and the recovery manifest is expired or
inconsistent, the watchdog leaves both files untouched and requires manual
administrator review. It never broad-deletes firewall rules.

Normal watchdog expiry is distinct from stale recovery: a valid active primary
state may reach expiry and trigger one controlled cleanup. A stale or
inconsistent recovery manifest never authorizes deletion. A state marked cleaned
does not authorize stale cleanup.

PowerShell cleanup reports:

- Invalid identity/state: cleanup refused.
- Rule remains: removal failed or incomplete.
- Rule absent: removal verified.
- Rule absent but state write fails: `cleaned_unpersisted`.
- State write verified: cleanup persisted.

If final local state persistence fails, cleanup verification and state-write
failure are reported separately. Cleanup is not marked simply `cleaned` when
the final manifest could not be persisted. Filesystem availability is an
unavoidable remaining dependency.

Recovery limitations and safety concerns:

- `try/finally` is reliable for Python exceptions and normal browser failure
  handling, but not for a process kill, power loss, terminal closure, or reboot.
- The watchdog is independent of the parent Python process and terminal; it
  protects for the configured expiry only while Windows is running.
- The watchdog requires the same elevation as rule creation. It does not create
  a service or scheduled task.
- A restart, power failure, or stopping the Windows Defender Firewall service
  can make the watchdog unavailable. Cleanup after restart is an explicit
  administrator action.
- A Task Scheduler mechanism could run at startup or after logon, but creating
  it would require elevated setup and would leave a system-level recovery entry.
  It is not selected for this PoC. If adopted later, it must use the exact
  unique group/name state, be confined to this script, and be removed after use.
- If state saving fails before rule creation, no rule is created. If state saving
  becomes corrupted after application, the cleanup script refuses unrelated
  cleanup; manual review is required.
- One Playwright process tree is not guaranteed to cover every other browser
  session or future browser mode.
- `-Protocol Any` is intentionally broader than TCP-only and may cover UDP.
- The experiment is not evidence of enforcement until remote peers are observed
  and mixed observations are detected.

### Sequential execution

Run one mode at a time:

1. Preview.
2. Apply only after explicit approval.
3. Run all destinations sequentially.
4. Verify output.
5. Run cleanup immediately.
6. Confirm no tracked rule remains.

Do not run IPv4-only and IPv6-only simultaneously. A browser session should
finish or be closed before changing to the next mode.

## D. Future approved PowerShell commands

These are evidence and preparation only. They must not be executed until explicit
approval is given.

### Immediate destination revalidation

Run this procedure immediately before each real experiment and again if DNS or
network state changes. Do not reuse earlier DNS results.

```powershell
Resolve-DnsName example.com -Type A
Resolve-DnsName example.com -Type AAAA
Resolve-DnsName ipv4.google.com -Type A
Resolve-DnsName ipv4.google.com -Type AAAA
Resolve-DnsName ipv6.google.com -Type A
Resolve-DnsName ipv6.google.com -Type AAAA
Test-NetConnection example.com -Port 443
Test-NetConnection ipv4.google.com -Port 443
Test-NetConnection ipv6.google.com -Port 443
curl.exe -4 -I https://example.com
curl.exe -6 -I https://example.com
curl.exe -4 -I https://ipv4.google.com
curl.exe -6 -I https://ipv4.google.com
curl.exe -4 -I https://ipv6.google.com
curl.exe -6 -I https://ipv6.google.com
Test-Path "C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe"
```

Acceptable preflight updates:

- `ipv4.google.com` only if it has A and no AAAA and IPv4 `curl.exe -4` succeeds.
- `ipv6.google.com` only if it has AAAA and no A and IPv6 `curl.exe -6` succeeds.
- `example.com` as dual-stack only if both A/AAAA records and independent
  IPv4/IPv6 connectivity are present.
- Stop and reapprove or redesign if DNS or connectivity contradicts the matrix.

Dry-run previews:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv4_only
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv6_only
```

Real rule-application commands are intentionally unavailable. No current
command should be used to apply or remove rules for this PoC.

Browser probes:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py --mode unrestricted --url https://example.com --disable-quic --output experiments\firewall_poc\approved_unrestricted_example.json
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py --mode ipv4_only --url https://ipv4.google.com --disable-quic --output experiments\firewall_poc\approved_ipv4_google.json
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py --mode ipv6_only --url https://ipv6.google.com --disable-quic --output experiments\firewall_poc\approved_ipv6_google.json
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py --mode ipv4_only --url https://ipv6.google.com --disable-quic --output experiments\firewall_poc\approved_ipv4_blocks_ipv6_target.json
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py --mode ipv6_only --url https://ipv4.google.com --disable-quic --output experiments\firewall_poc\approved_ipv6_blocks_ipv4_target.json
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py --mode ipv4_only --url https://example.com --disable-quic --output experiments\firewall_poc\approved_ipv4_dualstack.json
.\.venv\Scripts\python.exe experiments\firewall_poc\browser_probe.py --mode ipv6_only --url https://example.com --disable-quic --output experiments\firewall_poc\approved_ipv6_dualstack.json
```

After every browser probe, run:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\verify_connections.py <report-file>
```

Exact elevated cleanup commands:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File', "`"$PWD\experiments\firewall_poc\cleanup_firewall_rules.ps1`""
```

The script can be rerun; it returns already-clean once cleanup status is
`cleaned`. Missing or incomplete `state.json` produces no rule deletion.

State inspection (read-only; safe outside elevation):

```powershell
Get-Content -LiteralPath .\experiments\firewall_poc\state.json -Raw
Get-NetFirewallRule -Group "<unique-state-group>"
```

Do not substitute broad name/group searches for the exact state triple.

These commands do not run firewall cleanup or application as part of this test
plan.

## E. Remaining limitations and readiness

Remaining limitations:

- NAT64/DNS64/464XLAT is unknown.
- Public DNS records can change.
- The browser probe has CDP remote-IP observations unavailable.
- Playwright `server_addr()` is the primary remote-peer evidence.
- Process ownership has been confirmed only for the current headless shell build.
- A separate watchdog protects only while Windows is running; it does not survive restart.
- State corruption or missing state is fail-safe for deletion but may require manual recovery.
- No Task Scheduler recovery task is created or approved.
- Rule preview does not prove enforcement.

Readiness conclusion:

- The test destinations, revalidation procedure, test matrix, state schema,
  watchdog design, and exact cleanup script are prepared.
- Simulated cleanup tests cover normal completion, browser/Python failures,
  timeout, missing/incomplete state, repeated cleanup, and stale state.
- No firewall rule or system setting has been changed during this review.
- The experiment is ready for explicit user approval, not execution.
- Approval must include administrator-authorized rule creation and
  administrator-authorized cleanup. A reboot or terminal loss can require
  explicit post-restart cleanup, and no rule should remain unattended.
