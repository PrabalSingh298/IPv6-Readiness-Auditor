# Dashboard frontend

FastAPI serves [index.html](index.html) at `/` and serves [app.js](app.js) and [style.css](style.css) under `/static/`. The frontend uses vanilla JavaScript and SVG directly. There is no bundle or separate frontend server to start.

## Data flow

The form submits the target and mode to the [measurement API](../backend/api/README.md). The script polls job status and fetches the report on completion. It renders readiness, connection evidence, the failure breakdown, resource rows, and the dependency graph. The export buttons link to the API's JSON and CSV downloads.

| File | Responsibility |
| --- | --- |
| [index.html](index.html) | Measurement form, results panels, table structure, graph container, and controls. |
| [app.js](app.js) | Job polling, report rendering, filters, details, scrollbar state, and graph interaction. |
| [style.css](style.css) | Responsive dashboard layout, evidence colors, sticky headers, and scrollbar styling. |

Observed Resources searches URLs and hostnames and filters by result and type. More than ten matching rows activates a visible, keyboard-operable scrollbar beside the table. The table header stays fixed inside the scroll area. Resource IP and failure details expand in place. The SVG graph shows evidence-backed layers, with node colors representing DNS capability. Select a node or focus it and press Enter to inspect its details.

Launch the application using the [root setup instructions](../README.md#installation). Verify dashboard changes with the [controlled dashboard regression](../tests/README.md).
