import csv
import io
import json
import logging
import os
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from backend.measurement.network_mode import MeasurementMode
from backend.measurement.resource_collector import (
    DATA_DIRECTORY,
    collect_resources,
    validate_url,
)


router = APIRouter(prefix="/api")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="measurement")
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_logger = logging.getLogger(__name__)


class MeasurementRequest(BaseModel):
    url: str
    mode: MeasurementMode = "unrestricted"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_saved_reports() -> int:
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    loaded_jobs = {}

    for report_path in DATA_DIRECTORY.glob("phase3_*.json"):
        try:
            with report_path.open(encoding="utf-8") as report_file:
                report = json.load(report_file)
            modified_at = datetime.fromtimestamp(
                report_path.stat().st_mtime, timezone.utc
            ).isoformat()
        except (OSError, json.JSONDecodeError) as error:
            _logger.warning("Could not load saved report %s: %s", report_path, error)
            continue

        if not isinstance(report, dict) or not isinstance(report.get("resources"), list):
            continue

        job_id = report.get("dashboard_job_id") or report.get("measurement_id")
        target_url = report.get("target_url")
        if not isinstance(job_id, str) or not isinstance(target_url, str):
            continue

        started_at = report.get("started_at") or modified_at
        report.setdefault("output_file", str(report_path))
        loaded_jobs[job_id] = {
            "id": job_id,
            "url": target_url,
            "mode": report.get("measurement_mode", "unrestricted"),
            "status": "completed",
            "created_at": started_at,
            "started_at": started_at,
            "completed_at": modified_at,
            "error": None,
            "report": report,
        }

    with _jobs_lock:
        _jobs.update(loaded_jobs)
    return len(loaded_jobs)


def _persist_report(job_id: str, report: dict) -> dict:
    report_path = Path(report["output_file"])
    if report_path.resolve().parent != DATA_DIRECTORY.resolve():
        raise ValueError("Collector report output must be inside the project data directory")

    persisted_report = {**report, "dashboard_job_id": job_id}
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=report_path.parent,
        prefix=f"{report_path.name}.",
        suffix=".tmp",
        delete=False,
    ) as report_file:
        temporary_path = Path(report_file.name)
        json.dump(persisted_report, report_file, indent=2)
    os.replace(temporary_path, report_path)
    return persisted_report


def _run_measurement(job_id: str, url: str, mode: str) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        job["status"] = "running"
        job["started_at"] = _utc_now()

    try:
        report = _persist_report(
            job_id,
            collect_resources(url, measurement_mode=mode),
        )
    except Exception as error:
        with _jobs_lock:
            job = _jobs[job_id]
            job["status"] = "failed"
            job["error"] = f"{type(error).__name__}: {error}"
            job["completed_at"] = _utc_now()
        return

    with _jobs_lock:
        job = _jobs[job_id]
        job["status"] = "completed"
        job["report"] = report
        job["completed_at"] = _utc_now()


def _get_job(job_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Measurement not found")
        return dict(job)


@router.get("/capabilities")
def get_capabilities() -> dict:
    return {
        "modes": [
            {
                "id": "unrestricted",
                "label": "Unrestricted",
                "available": True,
                "description": "Chromium uses its normal networking.",
            },
            {
                "id": "ipv4_only",
                "label": "IPv4-only",
                "available": True,
                "description": "The proxy opens upstream TCP web connections over IPv4 only.",
            },
            {
                "id": "ipv6_only",
                "label": "IPv6-only",
                "available": True,
                "description": "The proxy opens upstream TCP web connections over IPv6 only.",
            },
        ]
    }


@router.post("/measurements", status_code=202)
def start_measurement(request: MeasurementRequest) -> dict:
    try:
        url = validate_url(request.url)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id,
            "url": url,
            "mode": request.mode,
            "status": "queued",
            "created_at": _utc_now(),
            "started_at": None,
            "completed_at": None,
            "error": None,
            "report": None,
        }

    _executor.submit(_run_measurement, job_id, url, request.mode)
    return {
        "id": job_id,
        "status": "queued",
        "status_url": f"/api/measurements/{job_id}",
    }


@router.get("/measurements/{job_id}")
def get_measurement_status(job_id: str) -> dict:
    job = _get_job(job_id)
    report = job.get("report")
    return {
        "id": job["id"],
        "url": job["url"],
        "mode": job["mode"],
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "completed_at": job["completed_at"],
        "error": job["error"],
        "summary": report.get("summary") if report else None,
        "report_available": report is not None,
    }


@router.get("/measurements/{job_id}/report")
def get_measurement_report(job_id: str) -> dict:
    report = _get_job(job_id).get("report")
    if report is None:
        raise HTTPException(status_code=409, detail="Measurement report is not ready")
    return report


@router.get("/measurements/{job_id}/resources/{resource_index}")
def get_resource_detail(job_id: str, resource_index: int) -> dict:
    report = _get_job(job_id).get("report")
    if report is None:
        raise HTTPException(status_code=409, detail="Measurement report is not ready")
    resources = report.get("resources", [])
    if resource_index < 0 or resource_index >= len(resources):
        raise HTTPException(status_code=404, detail="Resource not found")
    return resources[resource_index]


@router.get("/measurements/{job_id}/export.json")
def download_json_report(job_id: str) -> Response:
    job = _get_job(job_id)
    report = job.get("report")
    if report is None:
        raise HTTPException(status_code=409, detail="Measurement report is not ready")
    import json

    content = json.dumps(report, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="measurement-{job_id}.json"'
        },
    )


@router.get("/measurements/{job_id}/export.csv")
def download_csv_report(job_id: str) -> Response:
    report = _get_job(job_id).get("report")
    if report is None:
        raise HTTPException(status_code=409, detail="Measurement report is not ready")

    output = io.StringIO(newline="")
    columns = [
        "url",
        "hostname",
        "method",
        "resource_type",
        "http_status",
        "success",
        "failure_category",
        "failure_reason",
        "initiator_url",
        "initiator_type",
        "dependency_depth",
    ]
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for resource in report.get("resources", []):
        classification = resource.get("failure_classification") or {}
        dependency = resource.get("dependency") or {}
        row = {
            "url": resource.get("url"),
            "hostname": resource.get("hostname"),
            "method": resource.get("method"),
            "resource_type": resource.get("resource_type"),
            "http_status": resource.get("http_status"),
            "success": resource.get("success"),
            "failure_category": classification.get("category"),
            "failure_reason": classification.get("reason"),
            "initiator_url": dependency.get("initiator_url"),
            "initiator_type": dependency.get("initiator_type"),
            "dependency_depth": dependency.get("depth"),
        }
        for key, value in row.items():
            if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                row[key] = "'" + value
        writer.writerow(row)

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="measurement-{job_id}.csv"'
        },
    )
