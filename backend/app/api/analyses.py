
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from starlette.concurrency import run_in_threadpool

from backend.app.services import storage_service
from backend.app.services.analysis_service import run_analysis


router = APIRouter(prefix="/api/analyses", tags=["Analyses"])

MAX_FILE_SIZE = 100 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


def _public_analysis(metadata: dict) -> dict:
    """Return analysis data without exposing server filesystem paths."""
    results = metadata.get("results") or {}

    safe_result_fields = [
        "input_file",
        "rows_processed",
        "matched_rows",
        "incidents_detected",
        "alerts_generated",
        "severity_distribution",
        "invalid_timestamps",
        "columns_detected",
        "timestamp_available",
        "score_interpretation",
        "detection_type",
        "status",
    ]

    safe_results = {
        key: results[key]
        for key in safe_result_fields
        if key in results
    }

    return {
        "analysis_id": metadata["analysis_id"],
        "filename": metadata.get("filename"),
        "status": metadata.get("status"),
        "created_at": metadata.get("created_at"),
        "updated_at": metadata.get("updated_at"),
        "completed_at": metadata.get("completed_at"),
        "failed_at": metadata.get("failed_at"),
        "error": metadata.get("error"),
        "results": safe_results or None,
    }


@router.post("")
async def create_analysis(file: UploadFile = File(...)):
    filename = file.filename or "uploaded.csv"

    if Path(filename).suffix.lower() != ".csv":
        raise HTTPException(
            status_code=415,
            detail="Only CSV files are currently supported.",
        )

    storage_service.STORAGE_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = None
    total_size = 0

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".csv",
            prefix="soc_upload_",
            dir=storage_service.STORAGE_ROOT,
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)

            while True:
                chunk = await file.read(CHUNK_SIZE)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 100 MB upload limit.",
                    )

                temp_file.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty.",
            )

        result = await run_in_threadpool(
            run_analysis,
            temp_path,
            filename,
        )

        return _public_analysis(result)

    finally:
        await file.close()

        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


@router.get("")
async def get_analyses():
    analyses = storage_service.list_analysis_metadata()

    return {
        "total": len(analyses),
        "analyses": [
            _public_analysis(item)
            for item in analyses
        ],
    }


@router.get("/{analysis_id}")
async def get_analysis(analysis_id: str):
    metadata = storage_service.read_analysis_metadata(analysis_id)

    if metadata is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return _public_analysis(metadata)



@router.get("/{analysis_id}/alerts")
async def get_analysis_alerts(
    analysis_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    search: str | None = Query(
        default=None,
        min_length=1,
        max_length=120,
    ),
):
    """Return a filtered page of alerts without loading the full file."""

    metadata = storage_service.read_analysis_metadata(analysis_id)

    if metadata is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    if metadata.get("status") != "completed":
        raise HTTPException(
            status_code=409,
            detail="Alerts are not available because analysis is not completed.",
        )

    alert_file = (
        storage_service.ANALYSES_DIR
        / analysis_id
        / "results"
        / "soc_alerts"
        / "soc_alerts.jsonl"
    )

    if not alert_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="Alert output file was not found.",
        )

    normalized_severity = (
        severity.strip().casefold() if severity else None
    )
    search_term = search.strip().casefold() if search else None

    total = 0
    page = []

    with alert_file.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            alert = json.loads(line)

            risk = alert.get("RiskAssessment", {})
            detection = alert.get("DetectionSummary", {})

            alert_severity = str(risk.get("Severity", ""))
            incident_id = str(alert.get("IncidentID", ""))
            alert_id = str(alert.get("AlertID", ""))

            categories = " ".join(
                str(value)
                for value in detection.get("Categories", [])
            )

            techniques = " ".join(
                str(value)
                for value in detection.get("MITRETechniques", [])
            )

            if (
                normalized_severity
                and alert_severity.casefold() != normalized_severity
            ):
                continue

            if search_term:
                searchable = (
                    f"{incident_id} {alert_id} "
                    f"{categories} {techniques}"
                ).casefold()

                if search_term not in searchable:
                    continue

            if total >= offset and len(page) < limit:
                page.append(alert)

            total += 1

    return {
        "analysis_id": analysis_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "severity": severity,
        "search": search,
        "alerts": page,
    }


@router.get("/{analysis_id}/reports")
async def get_analysis_reports(analysis_id: str):
    metadata = storage_service.read_analysis_metadata(analysis_id)

    if metadata is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    if metadata.get("status") != "completed":
        raise HTTPException(
            status_code=409,
            detail="Reports are not available because analysis is not completed.",
        )

    results_dir = (
        storage_service.ANALYSES_DIR
        / analysis_id
        / "results"
    )

    if not results_dir.is_dir():
        raise HTTPException(
            status_code=404,
            detail="Analysis results directory was not found.",
        )

    files = []

    for path in results_dir.rglob("*"):
        if path.is_file():
            files.append(str(path.relative_to(results_dir)).replace("\\", "/"))

    return {
        "analysis_id": analysis_id,
        "total_files": len(files),
        "files": sorted(files),
    }
