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
from backend.measurement.readiness import calculate_readiness, classify_dns_capability, is_ipv6_comparison, network_url_key
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


def _report_with_readiness(report: dict) -> dict:
    target = network_url_key(report["target_url"])
    mode = report.get("measurement_mode", "unrestricted")
    with _jobs_lock:
        candidates = [job["report"] for job in _jobs.values() if job.get("report")]
    matching = [candidate for candidate in candidates if target and network_url_key(candidate["target_url"]) == target]

    def completed_at(candidate: dict) -> str:
        return candidate.get("completed_at") or candidate.get("started_at") or ""

    baseline = report if mode == "unrestricted" else max(
        (candidate for candidate in matching if candidate.get("measurement_mode", "unrestricted") == "unrestricted"),
        key=completed_at, default=None,
    )
    ipv6 = report if mode == "ipv6_only" else max(
        (candidate for candidate in matching if is_ipv6_comparison(candidate)),
        key=completed_at, default=None,
    )
    result = {**report, "readiness": calculate_readiness(baseline, ipv6) if baseline is not None else None}
    if any("dns_capability" not in resource for resource in report["resources"]):
        result["resources"] = [
            {**resource, "dns_capability": classify_dns_capability(resource)} for resource in report["resources"]
        ]
        capabilities = {resource["url"]: resource["dns_capability"] for resource in result["resources"]}
        if graph := report.get("dependency_graph"):
            result["dependency_graph"] = {
                **graph,
                "nodes": [{**node, "dns_capability": capabilities.get(node["url"], "unknown")} for node in graph["nodes"]],
            }
    return result


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
    return _report_with_readiness(report)


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
    content = json.dumps(_report_with_readiness(report), indent=2)
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

    readiness = _report_with_readiness(report)["readiness"] or {}
    dns_counts = readiness.get("dns_counts") or {}
    http_counts = readiness.get("http_outcome_counts") or {}
    outcomes = readiness.get("http_resource_outcomes") or {}
    failed_dependencies = readiness.get("http_undiscovered_with_failed_dependency") or {}
    readiness_columns = {
        "baseline_measurement_id": readiness.get("baseline_measurement_id"),
        "ipv6_measurement_id": readiness.get("ipv6_measurement_id"),
        "total_baseline_resources": readiness.get("total_baseline_resources"),
        "dns_ipv6_readiness_percent": readiness.get("dns_ipv6_readiness_percent"),
        "http_ipv6_readiness_percent": readiness.get("http_ipv6_readiness_percent"),
        **{f"baseline_dns_{category}": dns_counts.get(category) for category in ("ipv4_only", "dual_stack", "ipv6_only", "unknown")},
        **{f"baseline_http_{outcome}": http_counts.get(outcome) for outcome in ("retrieved", "failed", "undiscovered", "unverified")},
    }
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
        "available_ipv4",
        "available_ipv6",
        "resolution_source",
        "resolution_scope",
        "resolution_failure_reason",
        "remote_ip",
        "remote_ip_family",
        "remote_ip_source",
        "remote_ip_scope",
        "response_peers",
        "proxy_attempted_ips",
        "proxy_connected_peers",
        "proxy_hostname",
        "proxy_port",
        "proxy_evidence_source",
        "proxy_evidence_scope",
        "dns_capability",
        "baseline_ipv6_http_outcome",
        "baseline_failed_dependency_url",
        "failure_evidence_source",
        "failure_requested_family",
        "failure_timeout_stage",
        "browser_error",
        *readiness_columns,
    ]
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for resource in report.get("resources", []):
        classification = resource.get("failure_classification") or {}
        failure_evidence = classification.get("evidence") or {}
        dependency = resource.get("dependency") or {}
        evidence = resource.get("ip_evidence") or {}
        resolved = evidence.get("resolved_addresses") or {}
        peer = evidence.get("connected_peer") or {}
        response_peers = evidence.get("response_peers") or []
        proxy_origin = evidence.get("proxy_origin") or {}
        url_key = network_url_key(resource.get("url") or "")
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
            "available_ipv4": " | ".join(resolved.get("ipv4", [])),
            "available_ipv6": " | ".join(resolved.get("ipv6", [])),
            "resolution_source": resolved.get("source"),
            "resolution_scope": resolved.get("scope"),
            "resolution_failure_reason": resolved.get("failure_reason"),
            "remote_ip": peer.get("ip"),
            "remote_ip_family": peer.get("family"),
            "remote_ip_source": peer.get("source"),
            "remote_ip_scope": peer.get("scope"),
            "response_peers": json.dumps(response_peers) if response_peers else "",
            "proxy_attempted_ips": " | ".join(proxy_origin.get("attempted_addresses", [])),
            "proxy_connected_peers": " | ".join(
                f"{item['ip']} ({item['family']})" for item in proxy_origin.get("connected_peers", [])
            ),
            "proxy_hostname": proxy_origin.get("hostname"),
            "proxy_port": proxy_origin.get("port"),
            "proxy_evidence_source": proxy_origin.get("source"),
            "proxy_evidence_scope": proxy_origin.get("scope"),
            "dns_capability": classify_dns_capability(resource),
            "baseline_ipv6_http_outcome": outcomes.get(url_key),
            "baseline_failed_dependency_url": failed_dependencies.get(url_key),
            "failure_evidence_source": failure_evidence.get("source"),
            "failure_requested_family": failure_evidence.get("requested_family"),
            "failure_timeout_stage": failure_evidence.get("timeout_stage"),
            "browser_error": failure_evidence.get("browser_error_text") or failure_evidence.get("browser_error"),
            **readiness_columns,
        }
        for key, value in row.items():
            if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                row[key] = "'" + value
        writer.writerow(row)

    if not report.get("resources") and readiness:
        writer.writerow(readiness_columns)

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="measurement-{job_id}.csv"'
        },
    )
