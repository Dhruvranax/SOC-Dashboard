
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from backend.app.adapters.guide_adapter import analyze_guide_csv
from backend.app.services.storage_service import (
    create_analysis_workspace,
    write_analysis_metadata,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_filename(filename: str | None) -> str:
    """Keep only a filename, not a user-supplied directory path."""
    if not filename:
        return "uploaded.csv"

    cleaned = filename.replace("\\", "/")
    return Path(cleaned).name or "uploaded.csv"


def run_analysis(
    csv_path: str | Path,
    original_filename: str | None = None,
    chunk_size: int = 100_000,
) -> dict:
    """
    Copy an uploaded CSV into an isolated workspace and run GUIDE detection.

    Analysis metadata is persisted for both successful and failed runs.
    """
    source = Path(csv_path).resolve()

    if not source.is_file():
        raise FileNotFoundError("Source CSV file was not found.")

    if source.suffix.lower() != ".csv":
        raise ValueError("Only CSV files are supported.")

    workspace = create_analysis_workspace()

    analysis_id = workspace["analysis_id"]
    stored_filename = _safe_filename(original_filename or source.name)

    metadata = {
        "analysis_id": analysis_id,
        "filename": stored_filename,
        "status": "processing",
        "created_at": _utc_now(),
        "results": None,
        "error": None,
    }

    write_analysis_metadata(workspace["metadata_file"], metadata)

    try:
        shutil.copy2(source, workspace["input_file"])

        metadata["status"] = "processing"
        metadata["input_file"] = str(workspace["input_file"])
        write_analysis_metadata(workspace["metadata_file"], metadata)

        result = analyze_guide_csv(
            csv_path=workspace["input_file"],
            output_dir=workspace["output_dir"],
            chunk_size=chunk_size,
        )

        metadata["status"] = "completed"
        metadata["results"] = result
        metadata["completed_at"] = _utc_now()
        metadata["error"] = None

    except Exception as exc:
        metadata["status"] = "failed"
        metadata["error"] = str(exc)
        metadata["failed_at"] = _utc_now()

    write_analysis_metadata(workspace["metadata_file"], metadata)

    return metadata
