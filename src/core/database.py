"""Local SQLite scan-history storage, without original inputs or API credentials."""

import json
import sqlite3
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / "data" / "scan_history.sqlite3"
VALID_TYPES = frozenset({"URL", "QR Code", "Email", "File"})
VALID_RISKS = frozenset({"Low", "Medium", "High", "Critical"})


def _connect():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DATABASE_PATH, timeout=10)


@contextmanager
def _db():
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    """Create a local history database if it does not already exist."""
    with _db() as connection:
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
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_history_timestamp
            ON scan_history(timestamp DESC)
        """)


def save_scan(scan_type, result):
    """Save one completed valid scan; do not persist the submitted content."""
    if scan_type not in VALID_TYPES:
        raise ValueError("Unsupported scanner type.")
    if not isinstance(result, dict):
        raise ValueError("Invalid scan result.")
    score = result.get("score")
    risk = result.get("risk")
    findings = result.get("findings")
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("Invalid scan score.")
    if risk not in VALID_RISKS:
        raise ValueError("Invalid scan risk level.")
    if not isinstance(findings, list) or not all(isinstance(f, str) for f in findings):
        raise ValueError("Invalid scan findings.")
    # Scanner findings are intentionally sanitized, but storage still has a bound.
    safe_findings = [finding[:300] for finding in findings[:30]]
    init_db()
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db() as connection:
        cursor = connection.execute(
            """INSERT INTO scan_history (timestamp, scan_type, score, risk, findings)
               VALUES (?, ?, ?, ?, ?)""",
            (timestamp, scan_type, score, risk, json.dumps(safe_findings)),
        )
        return cursor.lastrowid


def get_recent_scans(limit=200):
    """Read a bounded number of records, newest first."""
    if type(limit) is not int:
        raise ValueError("Limit must be an integer.")
    limit = max(1, min(limit, 500))
    init_db()
    with _db() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT id, timestamp, scan_type, score, risk, findings
               FROM scan_history ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [{
        "id": row["id"], "timestamp": row["timestamp"],
        "scan_type": row["scan_type"], "score": row["score"],
        "risk": row["risk"], "findings": json.loads(row["findings"]),
    } for row in rows]


def count_scans():
    """Return total scan count (not just the number shown on the dashboard)."""
    init_db()
    with _db() as connection:
        return connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
