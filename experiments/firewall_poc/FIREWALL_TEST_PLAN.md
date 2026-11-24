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
- `--apply-firewall-rules` is explicitly required.
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

- Rules are appended to `experiments/firewall_poc/state.json` after a successful
  `New-NetFirewallRule` call.
- Cleanup accepts only display names beginning
  `IPv6-Auditor-Experimental-` and then requires the matching tracked group.
- Cleanup removes only the tracked display-name/group pairs.
- Cleanup is not automatic and was not executed.

Safety concerns:

- Apply and browser launch are separate operations. If the browser fails or the
  shell is closed, the rule may remain until manual cleanup.
- If rule creation succeeds but state saving fails, cleanup cannot identify the
  rule reliably.
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

Recheck the destinations and executable:

```powershell
Resolve-DnsName example.com -Type A
Resolve-DnsName example.com -Type AAAA
Resolve-DnsName ipv4.google.com -Type A
Resolve-DnsName ipv4.google.com -Type AAAA
Resolve-DnsName ipv6.google.com -Type A
Resolve-DnsName ipv6.google.com -Type AAAA
Test-Path "C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe"
```

Dry-run previews:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv4_only
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv6_only
```

Administrator application commands:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv4_only --apply-firewall-rules
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv6_only --apply-firewall-rules
```

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

Elevated cleanup command:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File', "`"$PWD\experiments\firewall_poc\cleanup_firewall_rules.ps1`""
```

These commands do not run firewall cleanup or application as part of this test
plan.

## E. Remaining limitations and readiness

Remaining limitations:

- NAT64/DNS64/464XLAT is unknown.
- Public DNS records can change.
- The browser probe has CDP remote-IP observations unavailable.
- Playwright `server_addr()` is the primary remote-peer evidence.
- Process ownership has been confirmed only for the current headless shell build.
- Cleanup is manual and not protected against state-write failure.
- Rule preview does not prove enforcement.

Readiness conclusion:

- The test destinations are sufficiently identified.
- The test matrix is complete.
- The controller and cleanup need no firewall execution for this plan.
- The experiment should proceed only after explicit approval and with an
  administrator who understands the temporary, narrowly scoped rule and manual
  cleanup requirement.
