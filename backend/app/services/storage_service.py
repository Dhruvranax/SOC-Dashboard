
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


BACKEND_DIR = Path(__file__).resolve().parents[2]

STORAGE_ROOT = Path(
    os.getenv("SOC_STORAGE_DIR", str(BACKEND_DIR / "storage"))
).expanduser().resolve()

ANALYSES_DIR = STORAGE_ROOT / "analyses"


def create_analysis_workspace() -> dict:
    """
    Create an isolated directory structure for one analysis.

    Directory creation uses exist_ok=False to prevent accidental reuse
    of an existing analysis directory.
    """
    analysis_id = str(uuid4())

    analysis_dir = ANALYSES_DIR / analysis_id
    upload_dir = analysis_dir / "uploads"
    output_dir = analysis_dir / "results"

    upload_dir.mkdir(parents=True, exist_ok=False)
    output_dir.mkdir(parents=True, exist_ok=False)

    return {
        "analysis_id": analysis_id,
        "analysis_dir": analysis_dir,
        "upload_dir": upload_dir,
        "output_dir": output_dir,
        "input_file": upload_dir / "original.csv",
        "metadata_file": analysis_dir / "metadata.json",
    }


def write_analysis_metadata(
    metadata_file: str | Path,
    metadata: dict,
) -> None:
    """Write metadata atomically to avoid partially written JSON files."""
    destination = Path(metadata_file)
    destination.parent.mkdir(parents=True, exist_ok=True)

    temp_file = destination.with_suffix(".json.tmp")

    payload = {
        **metadata,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        with temp_file.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False)

        os.replace(temp_file, destination)

    finally:
        if temp_file.exists():
            temp_file.unlink()


def read_analysis_metadata(
    analysis_id: str,
) -> dict | None:
    """Read metadata for an analysis using its UUID."""
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        analysis_id,
        flags=re.IGNORECASE,
    ):
        return None

    metadata_file = ANALYSES_DIR / analysis_id / "metadata.json"

    if not metadata_file.is_file():
        return None

    try:
        with metadata_file.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return None
