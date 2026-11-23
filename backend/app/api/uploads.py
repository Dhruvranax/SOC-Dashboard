
from pathlib import Path
import csv
import io

from fastapi import APIRouter, File, HTTPException, UploadFile

router = APIRouter(prefix="/api/uploads", tags=["File Uploads"])

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".csv"}

GUIDE_REQUIRED_COLUMNS = {
    "IncidentId",
    "Category",
    "MitreTechniques",
}


@router.post("/inspect")
async def inspect_upload(file: UploadFile = File(...)):
    filename = file.filename or ""
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail="Only CSV files are currently supported.",
        )

    content = await file.read(MAX_FILE_SIZE + 1)

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 100 MB upload limit.",
        )

    try:
        text = content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text))
        columns = next(reader, [])
    except (UnicodeDecodeError, csv.Error):
        raise HTTPException(
            status_code=400,
            detail="Unable to read CSV. Check its encoding and format.",
        )

    if not columns or not any(column.strip() for column in columns):
        raise HTTPException(
            status_code=400,
            detail="CSV header is missing or empty.",
        )

    normalized_columns = [column.strip() for column in columns]

    if len(normalized_columns) != len(set(normalized_columns)):
        raise HTTPException(
            status_code=400,
            detail="CSV contains duplicate column names.",
        )

    missing_columns = sorted(
        GUIDE_REQUIRED_COLUMNS - set(normalized_columns)
    )

    is_guide_compatible = not missing_columns

    return {
        "filename": filename,
        "file_size_bytes": len(content),
        "format": "CSV",
        "columns": normalized_columns,
        "column_count": len(normalized_columns),
        "detection_adapter": (
            "microsoft_guide" if is_guide_compatible else None
        ),
        "compatible": is_guide_compatible,
        "missing_required_columns": missing_columns,
        "message": (
            "Microsoft GUIDE-compatible CSV detected."
            if is_guide_compatible
            else "CSV readable, but Microsoft GUIDE schema was not detected."
        ),
    }
