"""
SQLite database layer.

Two tables:
  findings    — every vulnerability found by any scanner
  mitigations — the hardcoded vuln_type → mitigation mapping
"""

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional

DB_PATH = Path(__file__).parent.parent / "findings.db"


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init():
    """Create tables if they don't exist yet."""
    with _conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id            TEXT PRIMARY KEY,
                timestamp     TEXT NOT NULL,
                scanner       TEXT NOT NULL,
                vuln_type     TEXT NOT NULL,
                endpoint      TEXT,
                method        TEXT,
                severity      TEXT NOT NULL DEFAULT 'MEDIUM',
                evidence      TEXT,
                status        TEXT NOT NULL DEFAULT 'OPEN',
                mitigation_id TEXT,
                verified_at   TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                id         TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                scanners   TEXT,
                findings_open     INTEGER DEFAULT 0,
                findings_mitigated INTEGER DEFAULT 0,
                findings_verified INTEGER DEFAULT 0
            );
        """)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def upsert_finding(f: dict) -> str:
    """
    Insert a new finding or ignore if an identical (scanner, vuln_type,
    endpoint, method) tuple already exists with status != VERIFIED.
    Returns the finding id.
    """
    with _conn() as con:
        existing = con.execute(
            """SELECT id, status FROM findings
               WHERE scanner=? AND vuln_type=? AND endpoint=? AND method=?
               ORDER BY timestamp DESC LIMIT 1""",
            (f["scanner"], f["vuln_type"], f.get("endpoint", ""), f.get("method", ""))
        ).fetchone()

        if existing and existing["status"] != "VERIFIED":
            return existing["id"]

        fid = f.get("id") or str(uuid.uuid4())
        con.execute(
            """INSERT INTO findings
               (id, timestamp, scanner, vuln_type, endpoint, method,
                severity, evidence, status, mitigation_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                fid,
                f.get("timestamp", _now()),
                f["scanner"],
                f["vuln_type"],
                f.get("endpoint", ""),
                f.get("method", ""),
                f.get("severity", "MEDIUM"),
                f.get("evidence", ""),
                f.get("status", "OPEN"),
                f.get("mitigation_id"),
            )
        )
        return fid


def get_open_findings() -> List[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM findings WHERE status='OPEN' ORDER BY severity DESC, timestamp"
        ).fetchall()


def get_mitigated_findings() -> List[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM findings WHERE status='MITIGATED'"
        ).fetchall()


def get_all_findings() -> List[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM findings ORDER BY timestamp DESC"
        ).fetchall()


def mark_mitigated(finding_id: str, mitigation_id: str):
    with _conn() as con:
        con.execute(
            "UPDATE findings SET status='MITIGATED', mitigation_id=? WHERE id=?",
            (mitigation_id, finding_id)
        )


def mark_verified(finding_id: str):
    with _conn() as con:
        con.execute(
            "UPDATE findings SET status='VERIFIED', verified_at=? WHERE id=?",
            (_now(), finding_id)
        )


def mark_open(finding_id: str):
    """Re-open a finding whose mitigation didn't hold up under verification."""
    with _conn() as con:
        con.execute(
            "UPDATE findings SET status='OPEN', mitigation_id=NULL WHERE id=?",
            (finding_id,)
        )


def mark_false_positive(finding_id: str):
    with _conn() as con:
        con.execute(
            "UPDATE findings SET status='FALSE_POSITIVE' WHERE id=?",
            (finding_id,)
        )


# ---------------------------------------------------------------------------
# Scan runs
# ---------------------------------------------------------------------------

def start_run(scanners: List[str]) -> str:
    run_id = str(uuid.uuid4())
    with _conn() as con:
        con.execute(
            "INSERT INTO scan_runs (id, started_at, scanners) VALUES (?,?,?)",
            (run_id, _now(), ",".join(scanners))
        )
    return run_id


def finish_run(run_id: str):
    with _conn() as con:
        counts = con.execute(
            """SELECT
                SUM(status='OPEN')       as open,
                SUM(status='MITIGATED')  as mitigated,
                SUM(status='VERIFIED')   as verified
               FROM findings"""
        ).fetchone()
        con.execute(
            """UPDATE scan_runs
               SET finished_at=?, findings_open=?, findings_mitigated=?, findings_verified=?
               WHERE id=?""",
            (_now(), counts["open"], counts["mitigated"], counts["verified"], run_id)
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
