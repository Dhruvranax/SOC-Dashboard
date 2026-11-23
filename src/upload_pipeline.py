"""
Reusable upload pipeline for Microsoft GUIDE-compatible CSV files.

This module validates and normalizes an uploaded CSV, runs the existing
rule-based detection engine, and generates SOC alerts in an isolated output
directory. It does not train a machine-learning model.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Callable

import pandas as pd


REQUIRED_COLUMNS = ["IncidentId", "Category", "MitreTechniques"]
OPTIONAL_TIMESTAMP_COLUMN = "Timestamp"
DEFAULT_CHUNK_SIZE = 100_000


class UploadValidationError(ValueError):
    """Raised when an uploaded file is not compatible with this pipeline."""


def _load_module(module_name: str, script_path: Path):
    """Load a fresh module instance so per-run global state cannot leak."""
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load pipeline module: {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def inspect_csv(csv_path: str | Path) -> dict:
    """Inspect the CSV header and return schema metadata without loading rows."""
    path = Path(csv_path)
    if not path.is_file():
        raise FileNotFoundError(f"Uploaded CSV not found: {path}")
    if path.suffix.lower() != ".csv":
        raise UploadValidationError("Only .csv files are supported in this MVP.")

    try:
        columns = pd.read_csv(path, nrows=0, encoding="utf-8-sig").columns.tolist()
    except UnicodeDecodeError as exc:
        raise UploadValidationError(
            "Could not decode the CSV as UTF-8. Export it as UTF-8 CSV and retry."
        ) from exc
    except Exception as exc:
        raise UploadValidationError(f"Could not read CSV header: {exc}") from exc

    missing = [column for column in REQUIRED_COLUMNS if column not in columns]
    if missing:
        raise UploadValidationError(
            "This file does not match the supported Microsoft GUIDE detection "
            f"schema. Missing required columns: {', '.join(missing)}"
        )

    return {
        "file_name": path.name,
        "columns": columns,
        "column_count": len(columns),
        "required_columns": REQUIRED_COLUMNS.copy(),
        "missing_required_columns": [],
        "timestamp_available": OPTIONAL_TIMESTAMP_COLUMN in columns,
        "row_count": None,
    }


def normalize_csv(
    input_path: str | Path,
    output_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int], None] | None = None,
) -> dict:
    """
    Normalize CSV values chunk-by-chunk.

    Text values are stripped and empty strings become missing values.
    Valid Timestamp values are converted to UTC ISO strings; invalid original
    timestamp values are retained, matching the project's cleaning approach.
    """
    source = Path(input_path)
    destination = Path(output_path)
    schema = inspect_csv(source)
    destination.parent.mkdir(parents=True, exist_ok=True)

    temp_path = destination.with_suffix(destination.suffix + ".tmp")
    if temp_path.exists():
        temp_path.unlink()

    total_rows = 0
    invalid_timestamps = 0
    first_chunk = True

    try:
        reader = pd.read_csv(
            source,
            chunksize=chunk_size,
            dtype="string",
            low_memory=False,
            encoding="utf-8-sig",
        )
        for chunk in reader:
            text_columns = chunk.select_dtypes(
                include=["object", "string"]
            ).columns
            for column in text_columns:
                chunk[column] = chunk[column].str.strip()
                chunk[column] = chunk[column].replace("", pd.NA)

            if OPTIONAL_TIMESTAMP_COLUMN in chunk.columns:
                original = chunk[OPTIONAL_TIMESTAMP_COLUMN].copy()
                parsed = pd.to_datetime(
                    original, errors="coerce", utc=True
                )
                invalid_timestamps += int(parsed.isna().sum())
                standardized = parsed.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                chunk[OPTIONAL_TIMESTAMP_COLUMN] = standardized.fillna(original)

            chunk.to_csv(
                temp_path,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False,
                na_rep="",
            )
            total_rows += len(chunk)
            first_chunk = False
            if progress_callback:
                progress_callback(total_rows)

        if total_rows == 0:
            raise UploadValidationError("The uploaded CSV contains no data rows.")

        temp_path.replace(destination)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise

    return {
        **schema,
        "row_count": total_rows,
        "invalid_timestamps": invalid_timestamps,
        "normalized_file": str(destination),
    }


def run_upload_pipeline(
    csv_path: str | Path,
    output_dir: str | Path,
    project_root: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[str, int], None] | None = None,
) -> dict:
    """
    Run validation -> normalization -> rule detection -> SOC alert generation.

    Each invocation loads fresh copies of the existing modules, isolating
    their module-level incident aggregation state between uploaded files.
    """
    source = Path(csv_path).resolve()
    root = Path(project_root).resolve()
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    scripts_dir = root / "src"
    detection_script = scripts_dir / "threat_detection.py"
    alert_script = scripts_dir / "soc_alert_generator.py"
    for script in (detection_script, alert_script):
        if not script.is_file():
            raise FileNotFoundError(f"Required project script not found: {script}")

    schema = inspect_csv(source)
    normalized_path = out / "normalized_upload.csv"

    def row_progress(rows: int):
        if progress_callback:
            progress_callback("normalizing", rows)

    ingestion = normalize_csv(
        source, normalized_path, chunk_size, row_progress
    )

    # Load the existing detector in a fresh module namespace. Its detection
    # rules remain unchanged; only input/output paths are redirected.
    detector = _load_module(
        f"_upload_threat_detection_{id(out)}", detection_script
    )
    detector.INPUT_FILE = normalized_path
    detector.OUTPUT_DIR = out / "incident_reports"
    detector.CHUNK_SIZE = chunk_size

    if progress_callback:
        progress_callback("detecting", 0)

    total_rows, matched_rows = detector.process_dataset()
    summary = detector.generate_incident_summary()
    incident_dir = out / "incident_reports"
    incident_dir.mkdir(parents=True, exist_ok=True)
    summary_path = incident_dir / "incident_detection_summary.csv"
    summary.to_csv(summary_path, index=False, encoding="utf-8")
    detector.generate_json_reports(summary)

    if progress_callback:
        progress_callback("generating_alerts", len(summary))

    # Reuse the project's alert formatting and investigation guidance.
    alert_module = _load_module(
        f"_upload_soc_alert_generator_{id(out)}", alert_script
    )
    alert_module.INPUT_FILE = summary_path
    alert_module.OUTPUT_DIR = out / "soc_alerts"
    alert_module.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    alert_module.main()

    alerts_path = out / "soc_alerts" / "soc_alerts.csv"
    alert_summary_path = out / "soc_alerts" / "alert_generation_summary.json"
    with alert_summary_path.open("r", encoding="utf-8") as file:
        alert_summary = json.load(file)

    result = {
        "input_file": source.name,
        "rows_processed": total_rows,
        "matched_rows": matched_rows,
        "incidents_detected": int(len(summary)),
        "alerts_generated": int(alert_summary["TotalAlertsGenerated"]),
        "severity_distribution": alert_summary["SeverityDistribution"],
        "invalid_timestamps": ingestion["invalid_timestamps"],
        "columns_detected": schema["column_count"],
        "timestamp_available": schema["timestamp_available"],
        "normalized_csv": str(normalized_path),
        "incident_summary_csv": str(summary_path),
        "alerts_csv": str(alerts_path),
        "alerts_jsonl": str(out / "soc_alerts" / "soc_alerts.jsonl"),
        "alert_summary_json": str(alert_summary_path),
        "detailed_reports_dir": str(incident_dir / "incident_*.json"),
        "score_interpretation": (
            "Heuristic prioritization score, not probability of compromise."
        ),
        "detection_type": "Rule-based; no model training is performed.",
    }

    with (out / "run_summary.json").open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)

    if progress_callback:
        progress_callback("complete", total_rows)

    return result
