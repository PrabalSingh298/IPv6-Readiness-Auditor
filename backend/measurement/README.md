# Measurement engine

The measurement engine accepts a public HTTP(S) URL, a navigation timeout in milliseconds, a headless browser setting, and a mode. Its primary integration point is `collect_resources()`, which returns a report dictionary and writes JSON to the root `data/` directory.

| File | Responsibility |
| --- | --- |
| [resource_collector.py](resource_collector.py) | Validates targets, runs Chromium, captures Playwright and CDP events, and writes reports. |
| [ip_family_proxy.py](ip_family_proxy.py) | Implements a measurement-scoped SOCKS5 CONNECT listener and relays TCP using the selected upstream address family. |
| [network_mode.py](network_mode.py) | Validates mode names, summarizes observed peers, and records enforcement evidence. |
| [resource_ip_evidence.py](resource_ip_evidence.py) | Adds resolved addresses, direct response peers, and origin-level proxy evidence to resource records. |
| [dependency_graph.py](dependency_graph.py) | Builds initiator-backed edges and computes depth from known roots. |
| [failure_classifier.py](failure_classifier.py) | Maps HTTP statuses and supported browser or proxy evidence to resource outcomes. |
| [readiness.py](readiness.py) | Normalizes URLs, classifies DNS capability, and compares a baseline with an optional IPv6-only report. |

## Collector flow

1. Validate the URL and mode. Start the loopback proxy for `ipv4_only` or `ipv6_only`.
2. Launch Chromium, subscribe to Playwright request events and CDP network events, and navigate. The collector allows one extra second for follow-on requests.
3. Close Chromium and clean up the proxy. Preserve the navigation outcome even if the page did not complete.
4. Enrich the observed resources, classify failures, link initiators, and save the report. An unrestricted report includes baseline DNS readiness. The [API](../api/README.md) pairs separate runs when reports are requested.

`resources` is keyed by exact request URL during collection, so repeated requests can share a resource record. Readiness uses a normalized HTTP(S) URL as the comparison key. A known dependency requires both an observed initiator URL and a corresponding resource. Depth is computed by following those relationships from verified roots.

## Proxy and evidence contract

`IPFamilyProxy(mode)` accepts `ipv4_only`, `ipv6_only`, or `dual_stack`. The last mode returns empty launch options for an unrestricted browser. The context manager starts the restricted listener on a free loopback port. Pass `playwright_launch_options()` into Chromium and close the browser before leaving the context.

The proxy caches system resolution per hostname, filters candidates by family, and tries same-family TCP addresses. IPv6 sockets are set to IPv6-only and IPv4-mapped IPv6 candidates are rejected. Defaults include a five-second connection timeout, a 60-second tunnel idle timeout, and a 2,000-record attempt history. Windows has a 250-client cap per proxy instance.

`connection_attempts` exposes the selected mode, hostname, port, attempted IP, connected IP and family when available, and failure details. `hostname_resolutions` exposes the lookup snapshot. The report distinguishes:

- `resolved_addresses` for hostname or literal capability.
- `connected_peer` and `response_peers` for direct browser response evidence.
- `proxy_origin` for attempts and peers observed at hostname-and-port scope.

Do not infer an exact restricted resource peer from a shared proxy connection. A generic SOCKS error can have several causes. The classifier uses matching origin outcomes when they support a diagnosis and reports unknown otherwise.

## Run the collector

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m backend.measurement.resource_collector "https://example.com/" 30000 unrestricted
```

The CLI prints the report path. Inspect `navigation.completed`, resource results, and verification evidence to judge the run. See the [root methodology](../../README.md#measurement-methodology), the [proxy example](../../examples/README.md), and the [test guide](../../tests/README.md).
