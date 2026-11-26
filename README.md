# IPv6 Readiness Auditor

A browser-based tool for measuring whether a website and its browser-loaded resources are reachable over IPv4 and IPv6.

## Current status

### Project progress checklist

- [x] Phase 1: Workspace inspection and setup
- [x] Phase 2: Browser resource collection
- [x] Phase 3: IPv4/IPv6 measurement
- [x] Phase 4: Resource dependency graph
- [x] Phase 5: Resource failure classification
- [ ] Phase 6: Measurement campaign
- [x] Phase 7: Web dashboard
- [ ] Phase 8: Final validation

### Known limitations

- IP-family isolation applies to proxied Chromium TCP web traffic. DNS transport, other host traffic, and NAT64 translation are outside the measurement scope.
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

## Standalone IP-family proxy

Run the Playwright example from the project root using the existing Python environment and installed Chromium:

```powershell
.\.venv\Scripts\python.exe -m examples.playwright_ip_family ipv4_only https://example.com
```

`IPFamilyProxy` accepts `ipv4_only`, `ipv6_only`, or `dual_stack`. Restricted modes use SOCKS5 CONNECT on a temporary `127.0.0.1` port. Chromium supports SOCKS5 with proxy-side hostname resolution, and the proxy relays HTTP and TLS bytes over TCP. Chromium validates the destination's certificate as usual. Dual-stack returns empty Chromium launch options and uses the browser's normal networking.

```python
from playwright.sync_api import sync_playwright
from backend.measurement.ip_family_proxy import IPFamilyProxy

with IPFamilyProxy("ipv6_only") as proxy, sync_playwright() as playwright:
    browser = playwright.chromium.launch(**proxy.playwright_launch_options())
    try:
        page = browser.new_page()
        page.goto("https://example.com", timeout=15000)
    finally:
        browser.close()

attempts = proxy.connection_attempts
```

The context manages the listener and active tunnels. Synchronous callers can also use `start()`, `is_running`, and `stop()`. One instance is intended for one browser run at a time. `connection_attempts` is a bounded snapshot of DNS outcomes and TCP attempts. A successful record includes the upstream socket's peer address and family. DNS failure, unavailable family, and connection timeout or failure have distinct reason codes. Several browser resources can share one connection, and a TCP success says only that the socket connected.

This isolates TCP web resource connections in the configured Chromium instance. Its launch options remove Chromium's implicit loopback and link-local bypass, disable QUIC, and restrict non-proxied WebRTC UDP. System DNS can use either IP family and an in-flight OS lookup may finish after proxy shutdown. Other UDP traffic, WebRTC paths, other apps, and traffic outside the browser proxy remain outside this scope. VPNs can route or encapsulate traffic, and DNS64/NAT64 can translate an IPv6 connection to an IPv4 origin. The listener is unauthenticated and reachable by local processes while running. On Windows each proxy accepts up to 250 simultaneous clients within the socket selector's limit.

Run focused tests with `python -m unittest discover -s tests -p test_ip_family_proxy.py -v`. The Chromium test uses OpenSSL on `PATH` or the `OPENSSL` environment variable to generate a temporary local test certificate.

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

Select **Unrestricted**, **IPv4-only**, or **IPv6-only** before running the measurement.
The results show the selected mode and observed peers. Restricted reports also
show the proxy's connection attempts. Completed reports are saved in `data/`.

Run the controlled dependency and classification regressions with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

Run the Phase 2 live-site checks separately with:

```powershell
.\.venv\Scripts\python.exe tests\test_resource_collection.py
```

## Phase 5 resource failure classification

Each resource includes `failure_classification` with a reason and supporting
evidence. The dashboard distinguishes DNS failure, requested IP family
unavailability, connection failure, TLS failure, HTTP errors, timeout, browser
blocking or cancellation, and unknown causes. A timeout can identify the DNS,
connection, or request stage. Observed Resources scrolls independently, with
its search and filters above the sticky table header.

Restricted measurements use matching proxy observations at hostname-and-port
scope. Mixed outcomes, missing evidence, and generic SOCKS errors with an
ambiguous cause remain unknown. The original browser error, HTTP status, and
matching Chromium failure metadata are retained. Reports count only observed
failures. In a paired IPv6 comparison, undiscovered resources with a failed
baseline dependency are identified separately as an association.

Run the Phase 5 controlled and classification tests:

```powershell
.\.venv\Scripts\python.exe tests\test_failure_classification.py
```

The tests use browser error strings, mocked proxy outcomes, and a local HTTP
server for success, 404, and 500 responses.

## Phase 3 network mode setup

```powershell
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com" 30000 unrestricted
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com" 30000 ipv4_only
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com" 30000 ipv6_only
```

Restricted measurements start a loopback SOCKS5 proxy before Chromium and close it after the browser exits. No administrator privileges or system-wide networking changes are required. Unrestricted measurements launch Chromium directly and use its response peer evidence when available.

Reports and JSON exports include `network_mode.connection_attempts` and `network_mode.observed_remote_addresses`. Restricted peers come from connected upstream sockets. A TCP connection can carry multiple resources. The resource table and CSV retain browser-level classification, while the proxy attempts distinguish unavailable families, DNS failures, TCP failures, and timeouts. A completed report can describe failed navigation or unavailable resources. If no upstream peer connected, enforcement verification is recorded as `no_upstream_connections_observed`.

Expand **IP details** in the resource table or select a dependency graph node to view resource IP evidence. The JSON report includes `ip_evidence` on resources and graph nodes. CSV exports append equivalent address and attribution columns. Resolved addresses describe a hostname lookup or URL literal. Unrestricted response metadata can identify a resource peer. In restricted mode the proxy records attempted and connected peers by hostname and port, so the resource peer is left blank. The collector performs at most one enrichment lookup per hostname per measurement and reuses the proxy's lookup where available. Chromium may resolve hostnames independently in unrestricted mode. The system resolver can return different results across measurements.

### IPv6 readiness

Run **Unrestricted** for the baseline, then **IPv6-only** for the same URL. The dashboard and exports pair the displayed run with the latest eligible saved counterpart for that URL. The comparison IDs are included in the report. The dependency graph uses DNS capability colors independent of request success. Green indicates both families were returned, red indicates IPv4 only, blue indicates IPv6 only, and grey indicates a failed or inconclusive lookup. IP literals use their address family directly.

DNS readiness is the share of unique unrestricted HTTP(S) URLs with IPv6 capability. Unknown resources remain in the denominator. HTTP readiness is the share of those same URLs with a successful network response and IPv6 upstream evidence in the comparison run. Failed, undiscovered, and unverified results are counted separately. The HTTP score is blank until a comparable IPv6-only run has attempted navigation. URL matching preserves the query and ignores fragments and explicit default ports.

DNS classifications describe the system resolver's answers at measurement time. A successful lookup returning one family establishes absence from that result. The system resolver can hide individual record-type errors. IPv6 upstream evidence is scoped to the proxy connection and can include NAT64 paths.

Run `python -m unittest discover -s tests -p test_phase3_network_modes.py -v` for dashboard, collector, and cleanup verification against the existing controlled site served over both loopback families.
