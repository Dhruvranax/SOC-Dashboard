
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from backend.app.services import storage_service


# Store investigation data separately from generated SOC alert files.
DB_PATH = storage_service.STORAGE_ROOT / "investigations.sqlite3"


# Supported investigation statuses.
STATUSES = {
    "New",
    "In Progress",
    "Escalated",
    "Resolved",
}


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """
    Create a SQLite connection.

    Automatically commits successful transactions, rolls back failed
    transactions, and closes the connection.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def initialize_database() -> None:
    """
    Initialize the investigation database and required tables.

    Existing investigation records are preserved.
    """
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,

                UNIQUE (analysis_id, alert_id)
            );

            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,

                FOREIGN KEY (investigation_id)
                    REFERENCES investigations(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS investigation_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL,

                FOREIGN KEY (investigation_id)
                    REFERENCES investigations(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_investigations_analysis
                ON investigations(analysis_id);

            CREATE INDEX IF NOT EXISTS idx_notes_investigation
                ON investigation_notes(investigation_id);

            CREATE INDEX IF NOT EXISTS idx_activity_investigation
                ON investigation_activity(investigation_id);
            """
        )


def _validate_alert(analysis_id: str, alert_id: str) -> None:
    """
    Verify that the analysis exists, is completed, and contains the alert.

    This prevents investigation records from being created for arbitrary
    analysis IDs or alert IDs.
    """
    metadata = storage_service.read_analysis_metadata(analysis_id)

    if metadata is None:
        raise ValueError("Analysis not found.")

    if metadata.get("status") != "completed":
        raise ValueError("Analysis is not completed.")

    alert_file = (
        storage_service.ANALYSES_DIR
        / analysis_id
        / "results"
        / "soc_alerts"
        / "soc_alerts.jsonl"
    )

    if not alert_file.is_file():
        raise ValueError("Alert output file was not found.")

    found = False

    with alert_file.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                # Ignore malformed lines rather than crashing the lookup.
                continue

            if str(alert.get("AlertID", "")) == alert_id:
                found = True
                break

    if not found:
        raise ValueError("Alert not found in this analysis.")


def _get_or_create(
    connection: sqlite3.Connection,
    analysis_id: str,
    alert_id: str,
) -> sqlite3.Row:
    """
    Retrieve an investigation or create it with the default New status.
    """
    now = _now()

    connection.execute(
        """
        INSERT OR IGNORE INTO investigations (
            analysis_id,
            alert_id,
            status,
            created_at,
            updated_at
        )
        VALUES (?, ?, 'New', ?, ?)
        """,
        (analysis_id, alert_id, now, now),
    )

    investigation = connection.execute(
        """
        SELECT *
        FROM investigations
        WHERE analysis_id = ? AND alert_id = ?
        """,
        (analysis_id, alert_id),
    ).fetchone()

    if investigation is None:
        raise RuntimeError("Failed to retrieve investigation record.")

    return investigation


def _read_investigation(
    connection: sqlite3.Connection,
    investigation: sqlite3.Row,
) -> dict:
    """
    Build the complete investigation response using an existing connection.
    """
    notes = connection.execute(
        """
        SELECT id, note, created_at
        FROM investigation_notes
        WHERE investigation_id = ?
        ORDER BY id DESC
        """,
        (investigation["id"],),
    ).fetchall()

    activity = connection.execute(
        """
        SELECT id, action, details, created_at
        FROM investigation_activity
        WHERE investigation_id = ?
        ORDER BY id DESC
        """,
        (investigation["id"],),
    ).fetchall()

    return {
        "analysis_id": investigation["analysis_id"],
        "alert_id": investigation["alert_id"],
        "status": investigation["status"],
        "created_at": investigation["created_at"],
        "updated_at": investigation["updated_at"],
        "notes": [dict(row) for row in notes],
        "activity": [dict(row) for row in activity],
    }


def get_investigation(
    analysis_id: str,
    alert_id: str,
) -> dict:
    """
    Get an alert investigation.

    If no investigation exists yet, create one with status New.
    """
    _validate_alert(analysis_id, alert_id)

    with _connect() as connection:
        investigation = _get_or_create(
            connection,
            analysis_id,
            alert_id,
        )

        return _read_investigation(connection, investigation)


def update_status(
    analysis_id: str,
    alert_id: str,
    new_status: str,
) -> dict:
    """
    Update an investigation's status and record the change in activity.
    """
    if new_status not in STATUSES:
        allowed_statuses = ", ".join(sorted(STATUSES))

        raise ValueError(
            f"Invalid status. Choose one of: {allowed_statuses}"
        )

    _validate_alert(analysis_id, alert_id)

    with _connect() as connection:
        investigation = _get_or_create(
            connection,
            analysis_id,
            alert_id,
        )

        old_status = investigation["status"]

        if old_status != new_status:
            now = _now()

            connection.execute(
                """
                UPDATE investigations
                SET status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    new_status,
                    now,
                    investigation["id"],
                ),
            )

            connection.execute(
                """
                INSERT INTO investigation_activity (
                    investigation_id,
                    action,
                    details,
                    created_at
                )
                VALUES (?, 'status_changed', ?, ?)
                """,
                (
                    investigation["id"],
                    f"{old_status} -> {new_status}",
                    now,
                ),
            )

        updated_investigation = connection.execute(
            """
            SELECT *
            FROM investigations
            WHERE id = ?
            """,
            (investigation["id"],),
        ).fetchone()

        if updated_investigation is None:
            raise RuntimeError("Investigation record not found.")

        return _read_investigation(
            connection,
            updated_investigation,
        )


def add_note(
    analysis_id: str,
    alert_id: str,
    note: str,
) -> dict:
    """
    Add an analyst note and record the action in the activity history.
    """
    clean_note = note.strip()

    if not clean_note:
        raise ValueError("Note cannot be empty.")

    if len(clean_note) > 5000:
        raise ValueError("Note cannot exceed 5000 characters.")

    _validate_alert(analysis_id, alert_id)

    with _connect() as connection:
        investigation = _get_or_create(
            connection,
            analysis_id,
            alert_id,
        )

        now = _now()

        connection.execute(
            """
            INSERT INTO investigation_notes (
                investigation_id,
                note,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                investigation["id"],
                clean_note,
                now,
            ),
        )

        connection.execute(
            """
            UPDATE investigations
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now,
                investigation["id"],
            ),
        )

        connection.execute(
            """
            INSERT INTO investigation_activity (
                investigation_id,
                action,
                details,
                created_at
            )
            VALUES (?, 'note_added', 'Analyst note added', ?)
            """,
            (
                investigation["id"],
                now,
            ),
        )

        updated_investigation = connection.execute(
            """
            SELECT *
            FROM investigations
            WHERE id = ?
            """,
            (investigation["id"],),
        ).fetchone()

        if updated_investigation is None:
            raise RuntimeError("Investigation record not found.")

        return _read_investigation(
            connection,
            updated_investigation,
        )
