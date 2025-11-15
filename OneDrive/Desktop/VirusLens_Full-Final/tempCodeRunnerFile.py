# scan.py
"""
Simple DB-backed scan recorder for VirusLens.

Provides:
- get_engine() -> SQLAlchemy engine
- init_db(engine=None) -> creates scans table if missing
- record_scan(scan_type, target, status='queued') -> returns scan_id (int)
- update_scan(scan_id, **fields) -> update columns (status, vt_analysis_id, result_json, updated_at)
- list_scans(limit=50, offset=0) -> list of dicts (most recent first)
- get_scan(scan_id) -> dict or None

This is intentionally simple and self-contained (SQLAlchemy core + sqlite).
"""

from pathlib import Path
import json
import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, Text, DateTime
)
from sqlalchemy.engine import Engine
from sqlalchemy.sql import select, and_

# ---------- Configuration ----------
# --- import additions ---
import sqlite3
import json
from pathlib import Path
import datetime
import os 

def get_db_path() -> Path:
    # Use st.secrets or env var if available (UI pages often define get_db_path; keep this consistent)
    # If you already have get_db_path elsewhere, you can remove this function and call that instead.
    try:
        import streamlit as _st
        secret_path = _st.secrets.get("VL_DB_FILE") if hasattr(_st, "secrets") and isinstance(_st.secrets, dict) else None
    except Exception:
        secret_path = None
    env_path = os.environ.get("VL_DB_FILE")
    if secret_path:
        return Path(secret_path)
    if env_path:
        return Path(env_path)
    # fallback: project root (two levels above app/pages) then ./viruslens.db or app/viruslens.db
    THIS = Path(__file__).resolve()
    project_root = THIS.parents[1] if len(THIS.parents) >= 2 else THIS.parent
    # common locations to check; return the first existing path or default project_root/viruslens.db
    candidates = [
        project_root / "viruslens.db",
        project_root / "app" / "viruslens.db",
        Path.cwd() / "viruslens.db"
    ]
    for p in candidates:
        try:
            if p.exists():
                return p
        except Exception:
            pass
    return project_root / "viruslens.db"

# Global DB path variable (will be set by init_db)
DB_PATH = get_db_path()

def init_db(db_path: Path = None):
    """
    Ensure DB file and scans table exist. Call once at app startup.
    """
    global DB_PATH
    if db_path:
        DB_PATH = Path(db_path)
    else:
        DB_PATH = get_db_path()

    # ensure folder exists if DB in nested folder
    if DB_PATH.parent:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        input TEXT,
        scan_type TEXT,
        risk_score TEXT,
        summary TEXT,
        vt_details TEXT,        -- JSON string with extra fields for the PDF
        timestamp TEXT          -- ISO timestamp (UTC)
    )
    """)
    conn.commit()
    conn.close()
    return DB_PATH

def record_search(input_value: str, scan_type: str = "url", risk_score: str = "", summary: str = "", vt_details: dict = None):
    """
    Record a completed scan into the scans table.
    vt_details (optional) is stored as JSON for use by the PDF builder.
    Returns inserted row id (int).
    """
    global DB_PATH
    dbp = Path(DB_PATH)
    conn = sqlite3.connect(str(dbp), check_same_thread=False)
    cur = conn.cursor()
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    vt_json = json.dumps(vt_details or {}, ensure_ascii=False)
    cur.execute("""
        INSERT INTO scans (input, scan_type, risk_score, summary, vt_details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (input_value, scan_type, str(risk_score), summary or "", vt_json, now))
    inserted_id = cur.lastrowid
    conn.commit()
    conn.close()
    return inserted_id

def list_scans(limit: int = 200):
    """
    Return recent scans as list of dicts (most recent first).
    Each dict: id, input, type, risk, summary, vt_details (dict), timestamp
    """
    global DB_PATH
    dbp = Path(DB_PATH)
    if not dbp.exists():
        return []
    conn = sqlite3.connect(str(dbp), check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, input, scan_type, risk_score, summary, vt_details, timestamp
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        try:
            vt_details = json.loads(r[5]) if r[5] else {}
        except Exception:
            vt_details = {}
        results.append({
            "id": r[0],
            "input": r[1] or "",
            "type": r[2] or "",
            "risk": r[3] or "",
            "summary": r[4] or "",
            "vt_details": vt_details,
            "timestamp": r[6] or ""
        })
    return results
# -------------------------
# End replacement block
# -------------------------

def list_scans(limit: int = 200):
    """
    Return recent scans as list of dicts (most recent first).
    Each dict contains: id, input, type, risk, summary, timestamp, vt_details (dict)
    """
    dbp = DB_PATH if isinstance(DB_PATH, Path) else Path(DB_PATH)
    if not dbp.exists():
        return []

    conn = sqlite3.connect(str(dbp), check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, input, scan_type, risk_score, summary, vt_details, timestamp
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        try:
            vt_details = json.loads(r[5]) if r[5] else {}
        except Exception:
            vt_details = {}
        results.append({
            "id": r[0],
            "input": r[1] or "",
            "type": r[2] or "",
            "risk": r[3] or "",
            "summary": r[4] or "",
            "vt_details": vt_details,
            "timestamp": r[6] or ""
        })
    return results

# ------------------------------
# Example usage in scan workflow (wherever a scan completes):
#
#    # After a successful URL scan finishes and you have results:
#    inserted_id = record_search(
#        input_value = url_string,
#        scan_type = "url",
#        risk_score = overall_risk_string,
#        summary = short_summary_or_empty,
#        vt_details = dict_of_extra_fields_for_report  # optional
#    )
#
# Then the Reports page or History page should call list_scans(limit) to populate the dropdown.
#
# At app startup (e.g. main or before pages use DB), call:
#    init_db(get_db_path())   # or just init_db() if using default DB_PATH
#
# Important: make sure the Reports/History pages call init_db() or otherwise ensure DB creation before listing.

def _ensure_tables(engine: Engine = None):
    """
    Create 'scans' table if it does not exist.
    Columns:
      - id (int PK)
      - scan_type (text) : 'url'/'file'/...
      - target (text) : url or filename
      - status (text) : queued/running/done/error
      - vt_analysis_id (text) : optional external id
      - result_json (text) : JSON string (result payload)
      - created_at (datetime)
      - updated_at (datetime)
    """
    global _metadata, _scans_table
    engine = engine or get_engine()

    if _metadata is None:
        _metadata = MetaData()

    # Define scans table (idempotent)
    _scans_table = Table(
        "scans",
        _metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("scan_type", String(64), nullable=True),
        Column("target", Text, nullable=True),
        Column("status", String(64), nullable=True),
        Column("vt_analysis_id", String(256), nullable=True),
        Column("result_json", Text, nullable=True),
        Column("created_at", DateTime, nullable=True),
        Column("updated_at", DateTime, nullable=True),
        extend_existing=True
    )

    _metadata.create_all(engine)  # creates the table if missing


def init_db(engine: Engine = None) -> Engine:
    """
    Initialize DB (create engine and tables). Returns the engine.
    Call this on app startup.
    """
    engine = engine or get_engine()
    _ensure_tables(engine)
    return engine


# ---------- CRUD functions ----------

def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def record_scan(scan_type: str, target: str, status: str = "queued") -> int:
    """
    Insert a new scan row and return the new scan id.
    """
    engine = get_engine()
    _ensure_tables(engine)
    conn = engine.connect()
    now = _now()
    ins = _scans_table.insert().values(
        scan_type=scan_type,
        target=target,
        status=status,
        vt_analysis_id=None,
        result_json=None,
        created_at=now,
        updated_at=now
    )
    res = conn.execute(ins)
    scan_id = int(res.inserted_primary_key[0])
    conn.close()
    return scan_id


def update_scan(scan_id: int, status: Optional[str] = None,
                vt_analysis_id: Optional[str] = None,
                result_json: Optional[Any] = None) -> bool:
    """
    Update fields for a given scan id.
    - result_json: can be dict -> will be JSON-dumped before storing.
    Returns True if a row was updated.
    """
    engine = get_engine()
    _ensure_tables(engine)
    conn = engine.connect()
    upd_vals = {}
    if status is not None:
        upd_vals["status"] = status
    if vt_analysis_id is not None:
        upd_vals["vt_analysis_id"] = vt_analysis_id
    if result_json is not None:
        # If dict or list, dump as JSON string; if already str, keep
        if isinstance(result_json, (dict, list)):
            try:
                upd_vals["result_json"] = json.dumps(result_json, ensure_ascii=False)
            except Exception:
                upd_vals["result_json"] = str(result_json)
        else:
            # string or other
            upd_vals["result_json"] = str(result_json)
    if not upd_vals:
        # Nothing to update, but still update timestamp
        upd_vals["updated_at"] = _now()
    else:
        upd_vals["updated_at"] = _now()

    upd = _scans_table.update().where(_scans_table.c.id == int(scan_id)).values(**upd_vals)
    res = conn.execute(upd)
    conn.close()
    return (res.rowcount or 0) > 0


def list_scans(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Return recent scans as list of dicts ordered by id DESC.
    """
    engine = get_engine()
    _ensure_tables(engine)
    conn = engine.connect()
    sel = select([
        _scans_table.c.id,
        _scans_table.c.scan_type,
        _scans_table.c.target,
        _scans_table.c.status,
        _scans_table.c.vt_analysis_id,
        _scans_table.c.result_json,
        _scans_table.c.created_at,
        _scans_table.c.updated_at
    ]).order_by(_scans_table.c.id.desc()).limit(limit).offset(offset)
    rows = conn.execute(sel).fetchall()
    conn.close()
    results = []
    for r in rows:
        # attempt to parse result_json if present
        parsed = None
        if r["result_json"]:
            try:
                parsed = json.loads(r["result_json"])
            except Exception:
                parsed = r["result_json"]
        results.append({
            "id": int(r["id"]),
            "scan_type": r["scan_type"],
            "target": r["target"],
            "status": r["status"],
            "vt_analysis_id": r["vt_analysis_id"],
            "result_json": parsed,
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None
        })
    return results


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Return single scan row as dict or None.
    """
    engine = get_engine()
    _ensure_tables(engine)
    conn = engine.connect()
    sel = select([
        _scans_table.c.id,
        _scans_table.c.scan_type,
        _scans_table.c.target,
        _scans_table.c.status,
        _scans_table.c.vt_analysis_id,
        _scans_table.c.result_json,
        _scans_table.c.created_at,
        _scans_table.c.updated_at
    ]).where(_scans_table.c.id == int(scan_id))
    row = conn.execute(sel).fetchone()
    conn.close()
    if not row:
        return None
    parsed = None
    if row["result_json"]:
        try:
            parsed = json.loads(row["result_json"])
        except Exception:
            parsed = row["result_json"]
    return {
        "id": int(row["id"]),
        "scan_type": row["scan_type"],
        "target": row["target"],
        "status": row["status"],
        "vt_analysis_id": row["vt_analysis_id"],
        "result_json": parsed,
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None
    }
    # after a successful URL scan completion in your scan workflow
record_search( 
               # Robustly resolve the "input value" for recording/processing.
# Historically the UI code used a variable named `url_string`. When this
# module's functions are called from other pages (History, Reports, etc.)
# that name may not exist, so fall back to explicit parameters or empty string.
            _input_val = ""

# prefer an explicit parameter named `input_value` (if the current function
# defines/receives it) — this covers calls like record_search(input_value=...)
if 'input_value' in locals() and locals().get('input_value'):
    _input_val = locals().get('input_value')

# then prefer a common alias `value` or `target` if present
elif 'value' in locals() and locals().get('value'):
    _input_val = locals().get('value')
elif 'target' in locals() and locals().get('target'):
    _input_val = locals().get('target')

# then try `url_string` (UI pages sometimes define that variable)
elif 'url_string' in locals() and locals().get('url_string'):
    _input_val = locals().get('url_string')
elif 'url_string' in globals() and globals().get('url_string'):
    _input_val = globals().get('url_string')
scan_type = "url",
risk_score = overall_risk_text,
summary = short_summary_text,
vt_details = dict_with_keys_used_by_pdf_builder
)

# if nothing found, fall back to an empty string (or `None` if you prefer)
input_value = _input_val or ""

# ---------- Convenience main/test ----------
if __name__ == "__main__":
    # quick manual test / migration
    eng = init_db()
    print("DB path:", DEFAULT_DB_PATH)
    # create a sample scan if none exists
    scans = list_scans(limit=5)
    print("Recent scans:", scans)
