
import io
import json

import pandas as pd
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services import storage_service


client = TestClient(app)


def test_create_analysis_and_retrieve_results(tmp_path, monkeypatch):
    monkeypatch.setattr(
        storage_service,
        "ANALYSES_DIR",
        tmp_path / "analyses",
    )
    monkeypatch.setattr(
        storage_service,
        "STORAGE_ROOT",
        tmp_path / "storage",
    )

    csv_content = pd.DataFrame(
        [
            {
                "IncidentId": "API-TEST-001",
                "Category": "Ransomware",
                "MitreTechniques": "T1486",
                "Timestamp": "2025-01-15 10:30:00",
            }
        ]
    ).to_csv(index=False).encode("utf-8")

    response = client.post(
        "/api/analyses",
        files={
            "file": (
                "api_sample.csv",
                io.BytesIO(csv_content),
                "text/csv",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()
    analysis_id = data["analysis_id"]

    assert data["status"] == "completed"
    assert data["results"]["rows_processed"] == 1
    assert data["results"]["alerts_generated"] >= 1

    # Confirm the API does not expose server filesystem paths.
    assert "input_file" not in data

    detail_response = client.get(f"/api/analyses/{analysis_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["status"] == "completed"

    list_response = client.get("/api/analyses")
    assert list_response.status_code == 200
    assert list_response.json()["total"] == 1

    alerts_response = client.get(
        f"/api/analyses/{analysis_id}/alerts"
    )
    assert alerts_response.status_code == 200
    assert alerts_response.json()["total"] >= 1
    assert len(alerts_response.json()["alerts"]) >= 1

    reports_response = client.get(
        f"/api/analyses/{analysis_id}/reports"
    )
    assert reports_response.status_code == 200

    report_files = reports_response.json()["files"]
    assert "run_summary.json" in report_files
    assert "soc_alerts/soc_alerts.csv" in report_files


def test_reject_non_csv_analysis_upload():
    response = client.post(
        "/api/analyses",
        files={
            "file": (
                "sample.txt",
                io.BytesIO(b"not a csv"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 415


def test_analysis_not_found():
    response = client.get(
        "/api/analyses/00000000-0000-0000-0000-000000000000"
    )

    assert response.status_code == 404


def test_alerts_not_available_for_invalid_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(
        storage_service,
        "ANALYSES_DIR",
        tmp_path / "analyses",
    )

    response = client.get(
        "/api/analyses/00000000-0000-0000-0000-000000000000/alerts"
    )

    assert response.status_code == 404
