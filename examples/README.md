# Usage examples

[playwright_ip_family.py](playwright_ip_family.py) demonstrates the standalone proxy with Playwright Chromium. It opens one URL, prints the navigation status, and writes captured upstream connection attempts to standard output as JSON lines. It does not use the collector, dashboard API, dependency graph, or report store.

From the repository root after [installing the project and Chromium](../README.md#installation):

```powershell
.\.venv\Scripts\python.exe -m examples.playwright_ip_family ipv4_only https://example.com/
.\.venv\Scripts\python.exe -m examples.playwright_ip_family ipv6_only https://example.com/
.\.venv\Scripts\python.exe -m examples.playwright_ip_family dual_stack https://example.com/
```

`dual_stack` means normal Chromium networking and is equivalent in intent to the collector's `unrestricted` mode. It produces no proxy attempts. IPv6-only needs IPv6 connectivity from the measurement host.

The program closes Chromium before stopping the proxy. Reuse that ordering when integrating the proxy into another application. See [the measurement engine](../backend/measurement/README.md#proxy-and-evidence-contract) for the integration contract and the [root README](../README.md) for the full workflow.
