
from pathlib import Path
from tempfile import TemporaryDirectory

from src.upload_pipeline import run_upload_pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def analyze_guide_csv(
    csv_path: str | Path,
    chunk_size: int = 100_000,
) -> dict:
    """
    Run the existing Microsoft GUIDE detection pipeline.

    Each execution receives an isolated temporary output directory.
    Existing project reports and datasets are not overwritten.
    """
    source = Path(csv_path).resolve()

    if not source.is_file():
        raise FileNotFoundError("Uploaded CSV file was not found.")

    with TemporaryDirectory(prefix="soc_analysis_") as temp_dir:
        result = run_upload_pipeline(
            csv_path=source,
            output_dir=temp_dir,
            project_root=PROJECT_ROOT,
            chunk_size=chunk_size,
        )

        # Copy result metadata before the temporary directory is removed.
        return {
            "input_file": result["input_file"],
            "rows_processed": result["rows_processed"],
            "matched_rows": result["matched_rows"],
            "incidents_detected": result["incidents_detected"],
            "alerts_generated": result["alerts_generated"],
            "severity_distribution": result["severity_distribution"],
            "invalid_timestamps": result["invalid_timestamps"],
            "columns_detected": result["columns_detected"],
            "timestamp_available": result["timestamp_available"],
            "score_interpretation": result["score_interpretation"],
            "detection_type": result["detection_type"],
            "status": "completed",
        }
