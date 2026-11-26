
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.services import investigation_service


router = APIRouter(
    prefix="/api/analyses",
    tags=["Investigations"],
)


class UpdateStatusRequest(BaseModel):
    status: str = Field(
        min_length=1,
        max_length=50,
        description="New investigation status",
    )


class AddNoteRequest(BaseModel):
    note: str = Field(
        min_length=1,
        max_length=5000,
        description="Analyst investigation note",
    )


def _handle_service_error(error: ValueError) -> None:
    """
    Convert service validation errors into appropriate HTTP responses.
    """
    message = str(error)

    if message == "Analysis not found.":
        status_code = 404

    elif message == "Alert output file was not found.":
        status_code = 404

    elif message == "Alert not found in this analysis.":
        status_code = 404

    elif message == "Analysis is not completed.":
        status_code = 409

    else:
        status_code = 422

    raise HTTPException(
        status_code=status_code,
        detail=message,
    ) from error


@router.get(
    "/{analysis_id}/alerts/{alert_id}/investigation",
)
async def get_investigation(
    analysis_id: str,
    alert_id: str,
):
    """
    Retrieve an investigation for a specific alert.

    Creates a new investigation with status New if one does not exist.
    """
    try:
        return investigation_service.get_investigation(
            analysis_id=analysis_id,
            alert_id=alert_id,
        )

    except ValueError as error:
        _handle_service_error(error)


@router.patch(
    "/{analysis_id}/alerts/{alert_id}/investigation/status",
)
async def update_investigation_status(
    analysis_id: str,
    alert_id: str,
    request: UpdateStatusRequest,
):
    """
    Update an investigation's status.
    """
    try:
        return investigation_service.update_status(
            analysis_id=analysis_id,
            alert_id=alert_id,
            new_status=request.status,
        )

    except ValueError as error:
        _handle_service_error(error)


@router.post(
    "/{analysis_id}/alerts/{alert_id}/investigation/notes",
)
async def add_investigation_note(
    analysis_id: str,
    alert_id: str,
    request: AddNoteRequest,
):
    """
    Add an analyst note to an investigation.
    """
    try:
        return investigation_service.add_note(
            analysis_id=analysis_id,
            alert_id=alert_id,
            note=request.note,
        )

    except ValueError as error:
        _handle_service_error(error)
