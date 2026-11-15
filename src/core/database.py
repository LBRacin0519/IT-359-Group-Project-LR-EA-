import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


# Store the database outside the source-code directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / "data" / "scan_history.sqlite3"


def init_db():
    """Create the scan history database and table."""

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(DATABASE_PATH)

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk TEXT NOT NULL,
                findings TEXT NOT NULL
            )
        """)

        connection.commit()

    finally:
        connection.close()


def save_scan(scan_type, result):
    """Save a security scan result and return its ID."""

    valid_types = {"URL", "QR Code", "Email", "File"}
    valid_risks = {"Low", "Medium", "High", "Critical"}

    score = result.get("score")
    risk = result.get("risk")
    findings = result.get("findings")

    if scan_type not in valid_types:
        raise ValueError("Unsupported scan type.")

    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("Invalid risk score.")

    if risk not in valid_risks:
        raise ValueError("Invalid risk classification.")

    if not isinstance(findings, list) or not all(
        isinstance(item, str) for item in findings
    ):
        raise ValueError("Invalid security findings.")

    init_db()

    timestamp = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.execute(
            """
            INSERT INTO scan_history
            (timestamp, scan_type, score, risk, findings)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                scan_type,
                score,
                risk,
                json.dumps(findings)
            )
        )

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()


def get_recent_scans(limit=50):
    """Retrieve recent scan results, newest first."""

    init_db()

    limit = max(1, min(int(limit), 100))

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute(
            """
            SELECT id, timestamp, scan_type,
                   score, risk, findings
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

        return [
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "scan_type": row["scan_type"],
                "score": row["score"],
                "risk": row["risk"],
                "findings": json.loads(row["findings"])
            }
            for row in rows
        ]

    finally:
        connection.close()