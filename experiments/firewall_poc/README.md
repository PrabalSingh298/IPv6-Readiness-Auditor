# Windows Firewall Address-Family Enforcement PoC

This experimental directory is isolated from the production IPv6 Readiness Auditor.

## Safety

The default behavior is dry-run. Firewall rules are never created unless:

1. The process is running with administrator privileges.
2. The caller uses `--apply-firewall-rules`.

No existing firewall rule is modified or deleted. The cleanup scripts remove only
rules created by this PoC and tracked in `state.json`.

Actual firewall-rule execution is not authorized yet.

## Current read-only findings

- Windows 11, build 26200.
- Windows Defender Firewall service `MpsSvc` is running.
- The current PowerShell session is not administrator.
- Chromium executable:
  main Playwright path:
  `C:\Users\praba\AppData\Local\ms-playwright\chromium-1255\chrome-win64\chrome.exe`
- Verified network executable:
  `C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe`
- The machine has an IPv4 address and global IPv6 addresses.
- A global IPv6 default route is present on the hotspot.
- Windows proxy settings are disabled and no proxy environment variables were present.
- `curl.exe -4 -I https://example.com` returned HTTP 200.
- `curl.exe -6 -I https://example.com` returned HTTP 200.
- NAT64/464XLAT status remains unknown; no `64:ff9b::/96` route was observed.
- Teredo is disabled.

## Safe probe results

- The unrestricted Playwright probe loaded `https://example.com` with HTTP 200.
- CDP did not expose a `remoteIPAddress` for that probe.
- Exact Playwright Chromium executable processes were not found by the initial CIM
  process inventory during the probe, so process coverage is not yet verified.
- The verifier correctly marked the probe `inconclusive`.
- Six dry-run unit tests passed.
- A test using `--apply-firewall-rules` refused to create rules because the current
  PowerShell session is not administrator.
- No `state.json` file or firewall rule was created.

## Proposed rules

IPv4-only mode blocks the Chromium executable from remote IPv6 CIDR `::/0`.

```powershell
New-NetFirewallRule `
  -DisplayName "<unique-name>" `
  -Group "<unique-group>" `
  -Direction Outbound `
  -Action Block `
  -Protocol Any `
  -Program "C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe" `
  -RemoteAddress "::/0" `
  -Enabled True `
  -Profile Any
```

IPv6-only mode blocks the Chromium executable from remote IPv4 CIDR `0.0.0.0/0`.

```powershell
New-NetFirewallRule `
  -DisplayName "<unique-name>" `
  -Group "<unique-group>" `
  -Direction Outbound `
  -Action Block `
  -Protocol Any `
  -Program "C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe" `
  -RemoteAddress "0.0.0.0/0" `
  -Enabled True `
  -Profile Any
```

These rules can restrict the main Chromium executable and child processes that use
the same executable image. They do not prove process coverage for every possible
helper or browser path. HTTP/3 may use UDP and may need a separate experiment
with `--disable-quic`.

## Important limitation

No remote peer addresses were observed during the initial Chromium launch check.
Therefore the current environment is not yet verified. HTTP 200 or successful
navigation will never be treated as address-family success by this PoC.

## Server address observation results

Playwright 1.65.2 officially provides `Response.server_addr()`, returning
`Optional[RemoteAddr]`.

The live PoC results showed that this native API works. It returned bracketed
IPv6 literals such as `[2606:4700:90c5:72db:f2fd:20:ef6b:ff98]`; the bracket
notation is stripped before `ipaddress` classification.

Observed results:

- `https://example.com`, QUIC disabled: IPv6 peer
  `2606:4700:90c5:72db:f2fd:20:ef6b:ff98`, port 443, protocol `h2`.
- `https://example.com`, normal configuration: IPv6 peer
  `2606:4700:90c5:72db:f23b:20:ef6b:ff98`, port 443, protocol `h2`.
- `https://www.mozilla.org/en-US/`, QUIC disabled: 45 responses; observed IPv6
  peers included `2a04:4e42:59::347` and `2a04:4e42:59::787`, protocol `h2`.
- No Playwright `server_addr()` exception or `None` response was reproduced in
  these tests. The probe still records both cases if they occur.

CDP `Network.responseReceivedExtraInfo.remoteIPAddress` remained unavailable in
all live probes. CDP `Network.responseReceived` did provide the negotiated
protocol as `h2`. Therefore Playwright and CDP are only partially comparable:
server addresses agree with no second source, and two missing methods are not
successful verification.

The network connection for example.com was owned by PID 21784. Its executable
was `chrome-headless-shell.exe`, not Playwright's reported `chrome.exe`
path. Its parent process was PID 7212 and its command line contained
`--type=utility --utility-sub-type=network.mojom.NetworkService`.

This means the firewall executable scope cannot rely only on the main Chromium
path. An actual authorized rule must also account for the headless-shell
executable or a separate process-matching mechanism.

## Remote verification conclusion

Remote verification is now substantially more reliable for TCP/HTTP observations
because Playwright `server_addr()` was independently observed with real peer IP
addresses and protocol evidence.

It is still not sufficient to apply firewall rules until:

- The same result is repeated in stable firewall-PoC runs.
- CDP is either matched successfully or explicitly documented as unavailable.
- The exact Chromium executable scope is included.
- NAT64/464XLAT remains unknown.
- Unknown or missing observations remain inconclusive.

## Latest read-only process coverage investigation

Two sequential fresh probes were run against `https://example.com` with QUIC
disabled. Both completed with HTTP 200 and observed an IPv6 peer through
Playwright `Response.server_addr()`.

The connection-owning process changed PID between runs, but the executable and
role were consistent:

- Run 1: PID 26384, `chrome-headless-shell.exe`, NetworkService utility.
- Run 2: PID 16436, `chrome-headless-shell.exe`, NetworkService utility.
- Executable:
  `C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe`
- Parent browser process used the same `chrome-headless-shell.exe` executable.
- GPU and renderer child processes also used the same headless-shell executable.
- Playwright's reported `chrome.exe` path is not the executable that owned the
  observed TCP connection.

The future firewall scope must therefore include the headless-shell executable,
not only the main `chrome.exe` path. This is strong repeated evidence for the
current Playwright headless configuration, but it does not prove that every
future Playwright launch configuration uses the same process layout.

## Latest NAT64/DNS64 investigation

The active Wi-Fi interface had:

- IPv4 `10.48.162.252/24` with default gateway `10.48.162.49`.
- Global IPv6 addresses in `2401:4900:38c8:b4c7::/64`.
- IPv6 default route via `fe80::a42a:d8ff:feb2:5b21`.

`ipv4only.arpa` returned its expected A records:

- `192.0.0.170`
- `192.0.0.171`

No AAAA records were observed for `ipv4only.arpa`, so DNS64 synthesis was not
observed. This does not prove DNS64 or NAT64 is absent.

No route for the well-known `64:ff9b::/96` NAT64 prefix was observed. This does
not prove NAT64 is absent because operators may use a network-specific prefix.
Teredo was disabled. No 464XLAT/CLAT adapter indicator was found, but available
Windows diagnostics cannot conclusively identify 464XLAT, so its status remains
unknown.

## Investigation conclusion

- Chromium process ownership is sufficiently established for the current
  headless Playwright configuration to propose a future rule scoped to
  `chrome-headless-shell.exe`.
- It is not yet a complete firewall-enforcement proof because firewall rules
  have not been applied and child-process coverage can vary by launch mode.
- NAT64/DNS64/464XLAT status remains unknown except that DNS64 synthesis for
  `ipv4only.arpa` was not observed.
- Recommended next step: if explicitly approved, perform a narrowly scoped,
  administrator-authorized experiment covering the exact headless-shell path,
  with automatic cleanup and independent `server_addr()` verification.

## Dry-run executable targeting update

The controller now targets the verified NetworkService executable by default:

```text
C:\Users\praba\AppData\Local\ms-playwright\chromium_headless_shell-1255\chrome-headless-shell-win64\chrome-headless-shell.exe
```

It validates that this file exists before previewing or applying a rule. It also
accepts `--executable "C:\path\chrome-headless-shell.exe"` for future Playwright
builds.

Both rules use `-Protocol Any`, covering TCP and UDP. Preview commands:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv4_only
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv6_only
```

Administrator-only application commands, not executed:

```powershell
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv4_only --apply-firewall-rules
.\.venv\Scripts\python.exe experiments\firewall_poc\firewall_controller.py --mode ipv6_only --apply-firewall-rules
```

The cleanup script removes only display names prefixed
`IPv6-Auditor-Experimental-` and verifies that the tracked group matches. It was
not executed and no `state.json` file was created.

## NAT64/DNS64/464XLAT final report

The complete read-only investigation is saved in
[NAT64_INVESTIGATION.md](NAT64_INVESTIGATION.md).

The machine-readable evidence is saved in
[nat64_investigation.json](nat64_investigation.json).

## Final firewall enforcement test plan

The evidence-based destination selection, test matrix, future approved
PowerShell commands, cleanup procedure, and readiness conclusion are saved in
[FIREWALL_TEST_PLAN.md](FIREWALL_TEST_PLAN.md).
