
import json

import pandas as pd

from backend.app.services import storage_service
from backend.app.services.analysis_service import run_analysis


def test_analysis_results_are_persisted(tmp_path, monkeypatch):
    monkeypatch.setattr(
        storage_service,
        "ANALYSES_DIR",
        tmp_path / "analyses",
    )

    source = tmp_path / "sample_guide.csv"

    pd.DataFrame(
        [
            {
                "IncidentId": "TEST-INC-001",
                "Category": "Ransomware",
                "MitreTechniques": "T1486",
                "Timestamp": "2025-01-15 10:30:00",
            }
        ]
    ).to_csv(source, index=False)

    result = run_analysis(
        csv_path=source,
        original_filename="sample_guide.csv",
        chunk_size=100,
    )

    assert result["status"] == "completed"
    assert result["analysis_id"]
    assert result["results"]["rows_processed"] == 1
    assert result["results"]["incidents_detected"] >= 1
    assert result["results"]["alerts_generated"] >= 1

    analysis_dir = tmp_path / "analyses" / result["analysis_id"]
    metadata_file = analysis_dir / "metadata.json"
    uploaded_file = analysis_dir / "uploads" / "original.csv"
    output_dir = analysis_dir / "results"

    assert metadata_file.is_file()
    assert uploaded_file.is_file()
    assert (output_dir / "run_summary.json").is_file()
    assert (output_dir / "normalized_upload.csv").is_file()
    assert (output_dir / "soc_alerts" / "soc_alerts.csv").is_file()
    assert (output_dir / "soc_alerts" / "soc_alerts.jsonl").is_file()

    with metadata_file.open("r", encoding="utf-8") as file:
        saved_metadata = json.load(file)

    assert saved_metadata["status"] == "completed"
    assert saved_metadata["analysis_id"] == result["analysis_id"]
    assert saved_metadata["results"]["alerts_generated"] >= 1


def test_failed_analysis_status_is_persisted(tmp_path, monkeypatch):
    monkeypatch.setattr(
        storage_service,
        "ANALYSES_DIR",
        tmp_path / "analyses",
    )

    source = tmp_path / "invalid.csv"
    pd.DataFrame(
        [
            {
                "WrongColumn": "value",
            }
        ]
    ).to_csv(source, index=False)

    result = run_analysis(
        csv_path=source,
        original_filename="invalid.csv",
    )

    assert result["status"] == "failed"
    assert result["error"]

    metadata_file = (
        tmp_path
        / "analyses"
        / result["analysis_id"]
        / "metadata.json"
    )

    assert metadata_file.is_file()

    with metadata_file.open("r", encoding="utf-8") as file:
        saved_metadata = json.load(file)

    assert saved_metadata["status"] == "failed"
    assert "error" in saved_metadata
