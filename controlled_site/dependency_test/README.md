# Dependency graph fixture

This fixture provides observable dependency chains for browser integration tests.

| File | Role |
| --- | --- |
| [index.html](index.html) | Entry document that requests the stylesheet, script, and logo. |
| [style.css](style.css) | Styles the document and requests the CSS background. |
| [app.js](app.js) | Issues Fetch and XMLHttpRequest requests to the test handler. |
| [background.svg](background.svg), [logo.svg](logo.svg) | Distinct assets that exercise stylesheet and document initiators. |

The HTTP handler in [test_dependency_graph.py](../../tests/test_dependency_graph.py) serves the static files and responds to `/api/fetch` and `/api/xhr`. The [dashboard test](../../tests/test_phase3_network_modes.py) extends that handler to exercise restricted modes and readiness comparisons.

Run the graph regression from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_dependency_graph.py" -v
```

A static file server can display the assets, while the API requests require the test handler. The tests allow loopback targets within the test process. See the [root README](../../README.md) and [test guide](../../tests/README.md).
