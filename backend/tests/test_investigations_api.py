
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.api.investigations import router
from backend.app.services import investigation_service


ANALYSIS_ID = "test-analysis-001"
ALERT_ID = "SOC-3"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Create an isolated API test environment with:
    - A temporary SQLite database
    - A completed analysis
    - A sample SOC alert
    """

    analyses_dir = tmp_path / "analyses"

    alert_directory = (
        analyses_dir
        / ANALYSIS_ID
        / "results"
        / "soc_alerts"
    )

    alert_directory.mkdir(parents=True)

    alert_file = alert_directory / "soc_alerts.jsonl"

    alert = {
        "AlertID": ALERT_ID,
        "IncidentID": "INC-001",
        "Severity": "High",
    }

    alert_file.write_text(
        json.dumps(alert) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        investigation_service,
        "DB_PATH",
        tmp_path / "investigations.sqlite3",
    )

    monkeypatch.setattr(
        investigation_service.storage_service,
        "ANALYSES_DIR",
        analyses_dir,
    )

    monkeypatch.setattr(
        investigation_service.storage_service,
        "read_analysis_metadata",
        lambda analysis_id: (
            {"status": "completed"}
            if analysis_id == ANALYSIS_ID
            else None
        ),
    )

    investigation_service.initialize_database()

    app = FastAPI()
    app.include_router(router)

    with TestClient(app) as test_client:
        yield test_client


def investigation_url():
    return (
        f"/api/analyses/{ANALYSIS_ID}"
        f"/alerts/{ALERT_ID}/investigation"
    )


def test_get_investigation_creates_new_record(client):
    response = client.get(investigation_url())

    assert response.status_code == 200

    data = response.json()

    assert data["analysis_id"] == ANALYSIS_ID
    assert data["alert_id"] == ALERT_ID
    assert data["status"] == "New"
    assert data["notes"] == []
    assert data["activity"] == []


def test_update_investigation_status(client):
    response = client.patch(
        investigation_url() + "/status",
        json={"status": "In Progress"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "In Progress"
    assert len(data["activity"]) == 1
    assert data["activity"][0]["action"] == "status_changed"
    assert data["activity"][0]["details"] == "New -> In Progress"


def test_update_investigation_with_invalid_status(client):
    response = client.patch(
        investigation_url() + "/status",
        json={"status": "Unknown"},
    )

    assert response.status_code == 422
    assert "Invalid status" in response.json()["detail"]


def test_add_investigation_note(client):
    note = "Reviewed alert. Investigating the affected host."

    response = client.post(
        investigation_url() + "/notes",
        json={"note": note},
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["notes"]) == 1
    assert data["notes"][0]["note"] == note
    assert data["activity"][0]["action"] == "note_added"


def test_add_empty_investigation_note(client):
    response = client.post(
        investigation_url() + "/notes",
        json={"note": "   "},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Note cannot be empty."


def test_investigation_persistence(client):
    client.patch(
        investigation_url() + "/status",
        json={"status": "Escalated"},
    )

    client.post(
        investigation_url() + "/notes",
        json={"note": "Escalated for further review."},
    )

    response = client.get(investigation_url())

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "Escalated"
    assert len(data["notes"]) == 1
    assert data["notes"][0]["note"] == (
        "Escalated for further review."
    )
    assert len(data["activity"]) == 2


def test_investigation_rejects_unknown_analysis(client):
    response = client.get(
        "/api/analyses/unknown-analysis"
        "/alerts/SOC-3/investigation"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis not found."


def test_investigation_rejects_unknown_alert(client):
    response = client.get(
        f"/api/analyses/{ANALYSIS_ID}"
        "/alerts/UNKNOWN-ALERT/investigation"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Alert not found in this analysis."
    )
