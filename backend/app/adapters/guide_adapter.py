
from pathlib import Path

from src.upload_pipeline import run_upload_pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def analyze_guide_csv(
    csv_path: str | Path,
    output_dir: str | Path,
    chunk_size: int = 100_000,
) -> dict:
    """
    Run the existing Microsoft GUIDE detection pipeline.

    Results are written to a persistent, analysis-specific output directory.
    The caller is responsible for creating and managing that directory.
    """
    source = Path(csv_path).resolve()
    destination = Path(output_dir).resolve()

    if not source.is_file():
        raise FileNotFoundError("Uploaded CSV file was not found.")

    if source.suffix.lower() != ".csv":
        raise ValueError("Only CSV files are supported.")

    destination.mkdir(parents=True, exist_ok=True)

    result = run_upload_pipeline(
        csv_path=source,
        output_dir=destination,
        project_root=PROJECT_ROOT,
        chunk_size=chunk_size,
    )

    return {
        **result,
        "status": "completed",
    }
