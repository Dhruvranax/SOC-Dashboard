
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_inspect_guide_csv():
    csv_content = (
        b"IncidentId,Category,MitreTechniques,Timestamp\n"
        b"INC001,Malware,T1059,2026-11-23\n"
    )

    response = client.post(
        "/api/uploads/inspect",
        files={
            "file": (
                "guide.csv",
                csv_content,
                "text/csv",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["compatible"] is True
    assert data["detection_adapter"] == "microsoft_guide"
    assert data["column_count"] == 4


def test_inspect_non_guide_csv():
    csv_content = b"source_ip,destination_ip,protocol\n10.0.0.1,10.0.0.2,TCP\n"

    response = client.post(
        "/api/uploads/inspect",
        files={
            "file": (
                "network.csv",
                csv_content,
                "text/csv",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["compatible"] is False
    assert data["detection_adapter"] is None
    assert "IncidentId" in data["missing_required_columns"]


def test_reject_unsupported_file():
    response = client.post(
        "/api/uploads/inspect",
        files={
            "file": (
                "events.json",
                b'{"event": "login"}',
                "application/json",
            )
        },
    )

    assert response.status_code == 415


def test_reject_empty_file():
    response = client.post(
        "/api/uploads/inspect",
        files={
            "file": (
                "empty.csv",
                b"",
                "text/csv",
            )
        },
    )

    assert response.status_code == 400


def test_reject_duplicate_columns():
    csv_content = b"IncidentId,IncidentId,Category\nINC001,INC002,Malware\n"

    response = client.post(
        "/api/uploads/inspect",
        files={
            "file": (
                "duplicate.csv",
                csv_content,
                "text/csv",
            )
        },
    )

    assert response.status_code == 400
