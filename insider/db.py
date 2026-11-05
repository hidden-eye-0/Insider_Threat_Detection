"""SQLite persistence: schema, workspace handling, audit log with hash chain.

The audit log is *tamper-evident* (each row stores a SHA-256 over its content and the
previous row's hash; ``verify_audit_chain`` detects edits/deletions in the middle of the
chain). It is NOT tamper-proof: someone with file access could rebuild the entire chain.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from .config import ACTIVE_WORKSPACE_FILE, DEFAULT_WORKSPACE, WORKSPACE_DIR

STATUSES = ["Pending review", "Under investigation", "Explained / legitimate", "Escalated", "Closed"]
DISPOSITIONS = ["Not set", "Confirmed policy violation (needs HR/compliance action)",
                "False positive - legitimate activity", "Needs more information", "Inconclusive"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, employee_id TEXT NOT NULL, role TEXT,
  event_type TEXT NOT NULL, resource TEXT, customer_id TEXT, device_id TEXT, location TEXT,
  volume_mb REAL CHECK (volume_mb IS NULL OR volume_mb >= 0), record_count REAL, outcome TEXT,
  context_tag TEXT, source_ref TEXT, record_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_events_emp_ts ON events(employee_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type);
CREATE TABLE IF NOT EXISTS ground_truth (event_id TEXT PRIMARY KEY, is_malicious INTEGER, scenario_type TEXT, scenario_id TEXT);
CREATE TABLE IF NOT EXISTS baselines (employee_id TEXT PRIMARY KEY, role TEXT, status TEXT, history_days INTEGER, baseline_json TEXT);
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, employee_id TEXT NOT NULL, role TEXT, alert_type TEXT, kind TEXT,
  ts_detect TEXT, window_start TEXT, window_end TEXT, risk_score REAL NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  priority TEXT NOT NULL, ml_anomaly_score REAL, ml_norm REAL, explanation TEXT, signals_json TEXT,
  stages_json TEXT, context_coverage REAL, baseline_status TEXT, stale INTEGER DEFAULT 0, created_at TEXT);
CREATE INDEX IF NOT EXISTS ix_alerts_emp ON alerts(employee_id);
CREATE INDEX IF NOT EXISTS ix_alerts_prio ON alerts(priority);
CREATE TABLE IF NOT EXISTS alert_events (
  alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE, event_id TEXT NOT NULL,
  seq INTEGER, PRIMARY KEY (alert_id, event_id));
CREATE TABLE IF NOT EXISTS alert_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL, rule_name TEXT, severity TEXT, explanation TEXT, evidence_json TEXT,
  low_confidence INTEGER, event_ids_json TEXT);
CREATE INDEX IF NOT EXISTS ix_alert_rules_alert ON alert_rules(alert_id);
CREATE TABLE IF NOT EXISTS investigations (
  alert_id TEXT PRIMARY KEY REFERENCES alerts(alert_id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'Pending review', disposition TEXT NOT NULL DEFAULT 'Not set',
  conclusion TEXT DEFAULT '', updated_at TEXT);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  author TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_notes_alert ON notes(alert_id);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT, details TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS json_store (name TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
"""

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---- workspaces ------------------------------------------------------------
def safe_workspace_name(name: str) -> str:
    if not _NAME_RE.match(name or ""):
        raise ValueError("Workspace name must be 1-40 chars of letters, digits, '-' or '_'.")
    return name


def workspace_path(name: str) -> Path:
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    return WORKSPACE_DIR / f"{safe_workspace_name(name)}.db"


def list_workspaces() -> list[str]:
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(p.stem for p in WORKSPACE_DIR.glob("*.db"))


def get_active_workspace() -> str:
    try:
        name = ACTIVE_WORKSPACE_FILE.read_text(encoding="utf-8").strip()
        if _NAME_RE.match(name) and workspace_path(name).exists():
            return name
    except OSError:
        pass
    return DEFAULT_WORKSPACE


def set_active_workspace(name: str) -> None:
    safe_workspace_name(name)
    ACTIVE_WORKSPACE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACTIVE_WORKSPACE_FILE.write_text(name, encoding="utf-8")


# ---- connections ---------------------------------------------------------------
def connect(path: str | Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.executescript(SCHEMA)
    return con


@contextmanager
def session(path: str | Path):
    con = connect(path)
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ---- audit ------------------------------------------------------------------------
def _audit_hash(prev: str, ts: str, actor: str, action: str, target: str, details: str) -> str:
    return hashlib.sha256("|".join([prev, ts, actor, action, target or "", details or ""]).encode()).hexdigest()


def audit(con: sqlite3.Connection, actor: str, action: str, target: str = "", details: dict | str = "") -> None:
    det = details if isinstance(details, str) else json.dumps(details, default=str, sort_keys=True)
    row = con.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else "GENESIS"
    ts = now()
    con.execute("INSERT INTO audit_log(ts, actor, action, target, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, target, det, prev, _audit_hash(prev, ts, actor, action, target, det)))


def verify_audit_chain(con: sqlite3.Connection) -> tuple[bool, int | None]:
    """Return (ok, first_bad_row_id). Detects modified or removed rows within the chain."""
    prev = "GENESIS"
    for r in con.execute("SELECT * FROM audit_log ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _audit_hash(prev, r["ts"], r["actor"], r["action"], r["target"], r["details"]):
            return False, r["id"]
        prev = r["hash"]
    return True, None


# ---- investigations -------------------------------------------------------------------
def update_investigation(con, alert_id: str, status: str, disposition: str, conclusion: str, actor: str) -> None:
    if status not in STATUSES:
        raise ValueError(f"Invalid status: {status}")
    if disposition not in DISPOSITIONS:
        raise ValueError(f"Invalid disposition: {disposition}")
    if con.execute("SELECT 1 FROM alerts WHERE alert_id=?", (alert_id,)).fetchone() is None:
        raise KeyError(f"Unknown alert {alert_id}")
    old = con.execute("SELECT status, disposition FROM investigations WHERE alert_id=?", (alert_id,)).fetchone()
    con.execute("""INSERT INTO investigations(alert_id, status, disposition, conclusion, updated_at) VALUES (?,?,?,?,?)
                   ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, disposition=excluded.disposition,
                   conclusion=excluded.conclusion, updated_at=excluded.updated_at""",
                (alert_id, status, disposition, conclusion, now()))
    audit(con, actor, "update_investigation", alert_id,
          {"old": dict(old) if old else None, "new": {"status": status, "disposition": disposition}})


def add_note(con, alert_id: str, author: str, note: str) -> int:
    note = (note or "").strip()
    if not note:
        raise ValueError("Note is empty.")
    if con.execute("SELECT 1 FROM alerts WHERE alert_id=?", (alert_id,)).fetchone() is None:
        raise KeyError(f"Unknown alert {alert_id}")
    cur = con.execute("INSERT INTO notes(alert_id, author, note, created_at) VALUES (?,?,?,?)",
                      (alert_id, author or "analyst", note, now()))
    audit(con, author or "analyst", "add_note", alert_id, {"note_id": cur.lastrowid, "chars": len(note)})
    return int(cur.lastrowid)


def set_json(con, name: str, value) -> None:
    con.execute("""INSERT INTO json_store(name, value, updated_at) VALUES (?,?,?)
                   ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                (name, json.dumps(value, default=str), now()))


def get_json(con, name: str, default=None):
    r = con.execute("SELECT value FROM json_store WHERE name=?", (name,)).fetchone()
    return json.loads(r["value"]) if r else default
