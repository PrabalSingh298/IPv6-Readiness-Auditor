# IPv6 Readiness Auditor

A browser-based tool for measuring whether a website and its browser-loaded resources are reachable over IPv4 and IPv6.

## Current status

### Project progress checklist

- [x] Phase 1: Workspace inspection and setup
- [x] Phase 2: Browser resource collection
- [ ] Phase 3: IPv4/IPv6 measurement
- [x] Phase 4: Resource dependency graph
- [x] Phase 5: Resource failure classification
- [ ] Phase 6: Measurement campaign
- [x] Phase 7: Web dashboard
- [ ] Phase 8: Final validation

### Known limitations

- IPv4/IPv6 browser traffic enforcement is not implemented yet.
- IPv4-only Chromium measurement is candidate-only; `--disable-ipv6` is not claimed as independently verified.
- IPv6-only Chromium measurement is unsupported until a safe process-level mechanism and independent peer verification exist.
- This Windows environment has IPv4 access and link-local IPv6 addresses, but no global IPv6 default route was observed.
- NAT64 status is unknown.
- The controlled dual-stack and IPv4-only test site is not claimed to be safe or usable until address-family enforcement is verified.
- TLS failure classification is evidence-based and remains inconclusive when the browser does not expose a specific TLS error.
- The dashboard flow was validated with an unrestricted live `https://example.com` measurement; this does not verify address-family enforcement.
- A successful browser launch does not prove IPv4 or IPv6 network connectivity.
- Phase 2 uses normal Chromium networking and does not enforce IPv4 or IPv6.
- Browser resource timing is recorded only from available Playwright events.
- HTTP success, for 200-399, is separate from browser network success and is not a final readiness result.
- Dependency relationships are recorded only when Chromium CDP provides an initiator that matches a captured resource; otherwise parent and depth remain unknown.

## Phase 1 setup

Open PowerShell in this project folder.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
python tests/test_browser_launch.py
```

If PowerShell blocks virtual environment activation, inspect the policy rather than changing system security:

```powershell
Get-ExecutionPolicy -Scope CurrentUser
```

You may use the environment without activation:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe tests/test_browser_launch.py
```

## Phase 2 setup and browser resource collection

Run one website directly:

```powershell
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com" 30000
```

Run both Phase 2 test websites:

```powershell
.\.venv\Scripts\python.exe tests/test_resource_collection.py
```

The collector:

- Launches headless Chromium through Playwright.
- Captures `request` events for requested URLs and resource types.
- Captures `response` events for HTTP status and response evidence.
- Captures `requestfailed` events and preserves Playwright's original browser error.
- Records navigation completion, timeout, title, final URL, and duration.
- Saves a JSON report to `data/`.

Phase 2 does not determine whether a failure was DNS, TCP, TLS, timeout, or another browser/network issue. It preserves raw browser evidence for later phases.

## Phase 4 dependency graph

The collector now records CDP initiator URL, initiator type, source line/column
when available, matched parent URL, and dependency depth. It adds a
`dependency_graph` object with resource nodes, evidence-backed edges, and root
URLs to each JSON report.

Run the local controlled-fixture test and the existing Phase 2 website checks:

```powershell
.\.venv\Scripts\python.exe tests\test_dependency_graph.py
.\.venv\Scripts\python.exe tests\test_resource_collection.py
```

The controlled fixture is in `controlled_site\dependency_test\`. Its test server
is started only by the test and URL validation is bypassed only within that test
process; production URL validation remains unchanged.

## Dashboard

Start the FastAPI application from the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in a browser. The dashboard starts a measurement
through the local API, polls its status, and displays the actual collector
report. JSON and CSV downloads are available after completion. The API also
provides a resource-detail endpoint and capabilities listing.

IPv6-only mode is shown but disabled because the existing backend marks it
unsupported. IPv4-only is labelled unverified. These labels do not imply
address-family enforcement. Jobs and reports are held in memory and are lost
when the server stops.

Run the controlled dependency and classification regressions with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

Run the Phase 2 live-site checks separately with:

```powershell
.\.venv\Scripts\python.exe tests\test_resource_collection.py
```

## Phase 5 resource failure classification

Each resource now includes `failure_classification` with a category, short
reason, and the HTTP status/browser error evidence used. Categories are
`success`, `dns_failure`, `connection_failure`, `tls_failure`, `http_failure`,
and `inconclusive`. Generic browser errors and ambiguous navigation timeouts
remain inconclusive. The original `failure`, HTTP status, raw evidence, and
dependency graph are preserved.

Run the Phase 5 controlled and classification tests:

```powershell
.\.venv\Scripts\python.exe tests\test_failure_classification.py
```

The test uses browser-supplied error strings for classification boundaries and
a local controlled HTTP server for success, 404, and 500 responses. No
IPv4/IPv6 cause is inferred from generic network errors.

## Phase 3 network mode setup

### New Phase 3 file

- `backend/measurement/network_mode.py`
  - Validates the requested network mode.
  - Checks for Windows IPv6 addresses and a global IPv6 default route.
  - Builds an explicit network verification record.
  - Rejects IPv6-only mode instead of silently allowing IPv4 fallback.
  - Never changes firewall, routing, adapter, or global network settings.

- `backend/measurement/resource_collector.py`
  - Reuses Phase 2 browser resource collection.
  - Accepts `unrestricted`, `ipv4_only`, or `ipv6_only`.
  - For IPv4-only, launches Chromium with `--disable-ipv6` as a candidate mechanism.
  - Records CDP-observed remote address families when Chromium exposes them.
  - Does not claim IPv4-only readiness unless peer address evidence is verified.

### Run unrestricted measurement

```powershell
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com" 30000 unrestricted
```

### Run the IPv4-only candidate measurement

```powershell
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com" 30000 ipv4_only
```

This mode is candidate-only. The report remains `candidate_unverified` unless Chromium independently exposes only IPv4 remote peers.

### Attempt IPv6-only measurement

```powershell
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com" 30000 ipv6_only
```

IPv6-only mode is currently blocked and exits before Chromium starts.

### Run Phase 3 tests

```powershell
.\.venv\Scripts\python.exe tests/test_phase3_network_modes.py
```

The test output distinguishes:

- `PASSED`: supported and verified behavior
- `INCONCLUSIVE`: Chromium ran, but independent address-family verification was unavailable
- `NOT SUPPORTED`: no safe IPv6-only mechanism is available
- `SKIPPED`: a controlled test was not run because enforcement was not verified

## Phase 3 Windows findings

Read-only checks found:

- An active IPv4 address: `192.168.137.42`
- A link-local IPv6 address: `fe80::56b2:242a:ccbe:a86`
- No IPv6 global address was found.
- No `::/0` IPv6 default route was found.
- Example.com has AAAA DNS records, but those records do not prove IPv6 internet connectivity.
- NAT64 status remains unknown.

Chromium/Playwright provides browser launch control and can expose some peer information through CDP, but it does not provide a standard process-level IPv6-only enforcement option on Windows. The IPv4 candidate flag was not independently verified because no remote peer address was observed in this environment.
