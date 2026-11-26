# Testing

Run tests from the repository root with the virtual environment described in the [root README](../README.md#installation). The browser integration suite requires Playwright Chromium and working IPv4 and IPv6 loopback. The controlled tests run against local fixtures. They do not require public IPv6 connectivity.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

| Test file | Coverage |
| --- | --- |
| [test_readiness.py](test_readiness.py) | URL normalization, baseline denominators, DNS classification, comparison outcomes, and failed-dependency associations. |
| [test_failure_classification.py](test_failure_classification.py) | Browser and proxy evidence, ambiguity handling, and local HTTP success and error responses. |
| [test_dependency_graph.py](test_dependency_graph.py) | Known dependency chains and missing initiator evidence. |
| [test_ip_family_proxy.py](test_ip_family_proxy.py) | Address-family isolation, lack of cross-family fallback, timeouts, cleanup, and Chromium HTTP and HTTPS. |
| [test_phase3_network_modes.py](test_phase3_network_modes.py) | Three-mode dashboard workflow, report exports, resource inspection, graph colors, and independent resource scrolling. |

Use `-p` with a single filename for a focused run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_readiness.py" -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_phase3_network_modes.py" -v
```

The HTTPS fixture uses OpenSSL to create a temporary certificate. Put OpenSSL on PATH or set `OPENSSL` to its executable path. Without it, that browser test is skipped. The fixture permits the temporary certificate in its test context only.

The [controlled site](../controlled_site/README.md) provides predictable document, script, stylesheet, image, and API dependencies. The tests start their own servers and adjust URL validation only within the test process.

## Scripted smoke checks

These scripts have their own entry points and are run separately from `unittest` discovery.

```powershell
.\.venv\Scripts\python.exe tests/test_browser_launch.py
.\.venv\Scripts\python.exe tests/test_resource_collection.py
```

[test_browser_launch.py](test_browser_launch.py) checks that Chromium starts and renders local HTML. [test_resource_collection.py](test_resource_collection.py) visits public websites in unrestricted mode and writes measurement reports. Its observations depend on the network and the remote sites. Some collector tests also write ignored JSON reports under `data/`.

Return to the [root README](../README.md).
