from tempfile import TemporaryDirectory
from pathlib import Path

import pandas as pd

from backend.app.adapters.guide_adapter import PROJECT_ROOT
from src.upload_pipeline import run_upload_pipeline


def test_guide_pipeline_generates_detection_outputs():
    sample = pd.DataFrame(
        [
            {
                "IncidentId": "TEST-INC-001",
                "Category": "Ransomware",
                "MitreTechniques": "T1486",
                "Timestamp": "2025-01-15 10:30:00",
            }
        ]
    )

    with TemporaryDirectory(prefix="soc_pipeline_test_") as temp_dir:
        temp_path = Path(temp_dir)
        input_file = temp_path / "sample_guide.csv"
        output_dir = temp_path / "outputs"

        sample.to_csv(input_file, index=False)

        result = run_upload_pipeline(
            csv_path=input_file,
            output_dir=output_dir,
            project_root=PROJECT_ROOT,
            chunk_size=100,
        )

        assert result["rows_processed"] == 1
        assert result["incidents_detected"] >= 1
        assert result["alerts_generated"] >= 1
        assert output_dir.exists()
        assert any(output_dir.rglob("*.json"))