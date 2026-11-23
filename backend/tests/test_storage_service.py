
import json

from backend.app.services.storage_service import (
    create_analysis_workspace,
    read_analysis_metadata,
    write_analysis_metadata,
)


def test_create_analysis_workspace():
    workspace = create_analysis_workspace()

    assert workspace["analysis_id"]
    assert workspace["analysis_dir"].is_dir()
    assert workspace["upload_dir"].is_dir()
    assert workspace["output_dir"].is_dir()
    assert not workspace["input_file"].exists()


def test_analysis_workspaces_are_isolated():
    first = create_analysis_workspace()
    second = create_analysis_workspace()

    assert first["analysis_id"] != second["analysis_id"]
    assert first["analysis_dir"] != second["analysis_dir"]


def test_write_and_read_analysis_metadata():
    workspace = create_analysis_workspace()

    metadata = {
        "analysis_id": workspace["analysis_id"],
        "status": "uploaded",
        "filename": "sample.csv",
    }

    write_analysis_metadata(
        workspace["metadata_file"],
        metadata,
    )

    stored = read_analysis_metadata(workspace["analysis_id"])

    assert stored["analysis_id"] == workspace["analysis_id"]
    assert stored["status"] == "uploaded"
    assert stored["filename"] == "sample.csv"
    assert "updated_at" in stored


def test_invalid_analysis_id_returns_none():
    assert read_analysis_metadata("../../some-file") is None
