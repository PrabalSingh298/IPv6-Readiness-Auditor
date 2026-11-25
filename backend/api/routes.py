import csv
import io
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from backend.measurement.network_mode import (
    UnsupportedNetworkModeError,
    chromium_launch_args,
)
from backend.measurement.resource_collector import collect_resources, validate_url


router = APIRouter(prefix="/api")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="measurement")
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


class MeasurementRequest(BaseModel):
    url: str
    mode: Literal["unrestricted", "ipv4_only", "ipv6_only"] = "unrestricted"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_measurement(job_id: str, url: str, mode: str) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        job["status"] = "running"
        job["started_at"] = _utc_now()

    try:
        report = collect_resources(url, measurement_mode=mode)
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
                "description": "Chromium uses normal Windows networking.",
            },
            {
                "id": "ipv4_only",
                "label": "IPv4-only (unverified)",
                "available": True,
                "description": "Candidate mode only; enforcement is not independently verified.",
            },
            {
                "id": "ipv6_only",
                "label": "IPv6-only",
                "available": False,
                "description": "Unsupported: safe, independently verified enforcement is unavailable.",
            },
        ]
    }


@router.post("/measurements", status_code=202)
def start_measurement(request: MeasurementRequest) -> dict:
    try:
        url = validate_url(request.url)
        chromium_launch_args(request.mode)
    except UnsupportedNetworkModeError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
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
