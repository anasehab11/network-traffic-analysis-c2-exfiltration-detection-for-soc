"""SQLite investigation history (summaries, alerts, analyst notes). No packet payloads are stored."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL, filename TEXT, sha256 TEXT, size_bytes INTEGER,
  packets INTEGER, alerts INTEGER, risk_score REAL, risk_level TEXT, summary_json TEXT, conclusion TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS alert_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER, alert_id TEXT, status TEXT, note TEXT, updated_at REAL,
  UNIQUE(analysis_id, alert_id));
"""


@contextmanager
def _conn(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    try:
        c.executescript(SCHEMA)
        yield c
        c.commit()
    finally:
        c.close()


def save_analysis(path, result) -> int:
    m = result.meta
    with _conn(path) as c:
        cur = c.execute(
            "INSERT INTO analyses (created_at, filename, sha256, size_bytes, packets, alerts, risk_score, risk_level, summary_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), m["filename"], m["sha256"], m["size_bytes"], m["packets"], len(result.alerts), result.risk_score,
             result.risk_level, json.dumps(result.to_summary_dict(), default=str)))
        return cur.lastrowid


def list_analyses(path) -> list[dict]:
    with _conn(path) as c:
        return [dict(r) for r in c.execute(
            "SELECT id, created_at, filename, sha256, packets, alerts, risk_score, risk_level, conclusion FROM analyses ORDER BY id DESC")]


def get_analysis(path, analysis_id: int):
    with _conn(path) as c:
        r = c.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["summary"] = json.loads(d.pop("summary_json"))
        return d


def delete_analysis(path, analysis_id: int) -> None:
    with _conn(path) as c:
        c.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
        c.execute("DELETE FROM alert_notes WHERE analysis_id=?", (analysis_id,))


def set_conclusion(path, analysis_id: int, text: str) -> None:
    with _conn(path) as c:
        c.execute("UPDATE analyses SET conclusion=? WHERE id=?", (text[:5000], analysis_id))


def set_alert_note(path, analysis_id: int, alert_id: str, status: str, note: str) -> None:
    with _conn(path) as c:
        c.execute("INSERT INTO alert_notes (analysis_id, alert_id, status, note, updated_at) VALUES (?,?,?,?,?) "
                  "ON CONFLICT(analysis_id, alert_id) DO UPDATE SET status=excluded.status, note=excluded.note, updated_at=excluded.updated_at",
                  (analysis_id, alert_id, status, note[:2000], time.time()))


def get_alert_notes(path, analysis_id: int) -> dict:
    with _conn(path) as c:
        return {r["alert_id"]: {"status": r["status"], "note": r["note"]} for r in
                c.execute("SELECT alert_id, status, note FROM alert_notes WHERE analysis_id=?", (analysis_id,))}
