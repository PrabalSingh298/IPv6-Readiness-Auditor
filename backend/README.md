# Backend

The backend serves the dashboard, runs measurements, and exposes reports. [main.py](main.py) creates the FastAPI app, serves the frontend at `/` and `/static/`, mounts the API router, and restores saved reports at startup.

| Component | Responsibility |
| --- | --- |
| [API](api/README.md) | Validates requests, manages a two-worker queue, persists completed jobs, and exports results. |
| [Measurement](measurement/README.md) | Launches Chromium, collects network evidence, and builds the resource report. |

The normal entry point is `backend.main:app`. Run it from the repository root so the package imports resolve.

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Use one server process for the local dashboard. Job state is in memory per process. Completed JSON reports in `data/` provide restart continuity, while in-progress jobs have no resume mechanism. Restart the server to import reports created separately by the collector CLI.

See the [root README](../README.md) for setup and the [dashboard integration tests](../tests/README.md) for local verification.
