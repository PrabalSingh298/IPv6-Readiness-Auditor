# Measurement API

[routes.py](routes.py) implements the local FastAPI API under `/api`. [The application entry point](../main.py) mounts the router and reloads saved reports. The default base URL is `http://127.0.0.1:8000`. The server also exposes `/docs`, `/redoc`, and `/openapi.json`.

## Endpoints

| Method | Path | Parameters and response |
| --- | --- | --- |
| GET | `/api/capabilities` | Lists supported modes and descriptions. Mode availability describes implemented functionality. Network connectivity is measured during a run. |
| POST | `/api/measurements` | Requires a JSON `url` string. Optional `mode` is `unrestricted` by default and also accepts `ipv4_only` or `ipv6_only`. Returns HTTP 202 with `id`, `status`, and `status_url`. |
| GET | `/api/measurements/{job_id}` | Returns job metadata, timestamps, status, error if present, summary when available, and `report_available`. |
| GET | `/api/measurements/{job_id}/report` | Returns navigation, resources, dependency graph, network evidence, summary, and readiness. |
| GET | `/api/measurements/{job_id}/resources/{resource_index}` | Returns one stored resource by its zero-based position in `resources`. |
| GET | `/api/measurements/{job_id}/export.json` | Downloads the full report as JSON, including readiness pairing. |
| GET | `/api/measurements/{job_id}/export.csv` | Downloads resource rows, flattened evidence, readiness totals, and baseline outcomes. |
| GET | `/api/measurements/history` | Lists completed measurement summaries in reverse completion order. |
| GET | `/api/measurements/history/{measurement_id}` | Returns the saved report and readiness snapshot by measurement UUID. |
| GET | `/api/measurements/history/{measurement_id}/export.json` | Exports the historical report as JSON. |
| GET | `/api/measurements/history/{measurement_id}/export.csv` | Exports the historical report as CSV. |

Job IDs are UUID strings created by the API. Reports saved by the CLI are restored using their measurement ID. Use the API job ID when polling, even though the report also includes the collector's separate `measurement_id`.

Invalid request fields, modes, and ineligible targets receive HTTP 422. Unknown jobs and out-of-range resource indices receive HTTP 404. Report, resource, and export endpoints return HTTP 409 until the job has a report. A `completed` job may contain failed navigation or resources. Check `navigation` and `summary` to interpret results. A `failed` job indicates an exception prevented the worker from returning a saved report.

## Lifecycle and report data

Jobs move from `queued` to `running` and then to `completed` or `failed`. The worker invokes [the collector](../measurement/README.md), then writes the completed report in the project data directory with a `dashboard_job_id`. Startup restores usable `phase3_*.json` files into the job lookup.

The live report and both job-ID exports combine the selected run with the latest eligible saved counterpart for the same normalized target URL. The selected unrestricted run remains the baseline when viewed, and the selected IPv6-only run remains the comparison when viewed. Readiness data includes the source measurement IDs.

History uses the report's `measurement_id` field. It reads the readiness saved at completion and reuses it for both exports. Older reports retain any readiness they stored. If missing, the server can reconstruct it at startup from compatible saved runs available at the original completion time. Missing comparisons appear blank. Invalid UUIDs return HTTP 422, and unknown measurement IDs return HTTP 404.

JSON preserves structured browser and socket evidence. CSV flattens that evidence into columns, repeats available readiness totals alongside resource rows, and can include a totals-only row for a report without resources. Values that begin with common spreadsheet formula prefixes are escaped when exported.

## Example

```powershell
$base = 'http://127.0.0.1:8000'
$body = @{ url = 'https://example.com/'; mode = 'ipv6_only' } | ConvertTo-Json
$job = Invoke-RestMethod -Method Post -Uri "$base/api/measurements" -ContentType 'application/json' -Body $body
Invoke-RestMethod -Uri "$base$($job.status_url)"
```

After completion, use `$job.id` with the report, resource, or export endpoint. Keep the API bound to loopback. It has no built-in authentication.

See the [root README](../../README.md) and the [test instructions](../../tests/README.md).
