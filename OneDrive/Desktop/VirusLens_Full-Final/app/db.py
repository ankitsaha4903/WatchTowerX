# app/db.py
"""
Database helpers for VirusLens.
Provides:
 - get_db_path(): resolves DB path (env -> st.secrets -> default)
 - init_db(db_path=None): create DB and scans table if missing
 - connect_db(): returns sqlite3.Connection
 - record_search(...): insert a scan record (used by scan workflow)
 - get_scans(limit): list recent scans as dicts
 - get_scan(id): single scan detail
 - clear_history(): delete scans
"""

from __future__ import annotations
import os
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import streamlit as st
except Exception:
    st = None  # keep this file import-safe for non-streamlit contexts

DEFAULT_DB = Path("viruslens.db")

def get_db_path() -> Path:
    # 1. check environment variable
    env_val = os.environ.get("VL_DB_FILE")
    if env_val:
        return Path(env_val)
    # 2. try streamlit secrets (guarded)
    try:
        if st is not None and hasattr(st, "secrets") and isinstance(st.secrets, dict):
            sec = st.secrets.get("VL_DB_FILE") if "VL_DB_FILE" in st.secrets else None
            if sec:
                return Path(sec)
    except Exception:
        # swallow errors reading secrets
        pass
    # 3. fallback
    return DEFAULT_DB

def connect_db(path: Optional[Path] = None) -> sqlite3.Connection:
    p = path or get_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Optional[Path] = None) -> None:
    """
    Create the 'scans' table with the expected schema if it doesn't exist.
    This migration will add the column 'scan_type' if missing (safe).
    """
    conn = connect_db(db_path)
    cur = conn.cursor()
    # Create table if not exists with canonical schema
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT,
        target TEXT,
        status TEXT,
        vt_analysis_id TEXT,
        result_json TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
    """)
    conn.commit()
    # Ensure column presence in case older DB exists without scan_type etc.
    # Check columns and add any missing ones
    cur.execute("PRAGMA table_info(scans)")
    cols = [r["name"] for r in cur.fetchall()]
    if "scan_type" not in cols:
        cur.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT")
    if "vt_analysis_id" not in cols:
        cur.execute("ALTER TABLE scans ADD COLUMN vt_analysis_id TEXT")
    if "updated_at" not in cols:
        # sqlite doesn't support adding column with default expression prior to v3.35 properly,
        # but adding plain column is fine.
        cur.execute("ALTER TABLE scans ADD COLUMN updated_at TEXT")
    conn.commit()
    conn.close()

def record_search(scan_type: str, target: str, status: str = "", vt_analysis_id: str = "", result_json: Any = None) -> int:
    """
    Insert a scan record and return inserted id.
    result_json may be a dict — it will be JSON-dumped.
    """
    conn = connect_db()
    cur = conn.cursor()
    result_text = None
    try:
        if result_json is not None:
            if isinstance(result_json, str):
                result_text = result_json
            else:
                result_text = json.dumps(result_json)
    except Exception:
        result_text = str(result_json)
    cur.execute(
        "INSERT INTO scans (scan_type, target, status, vt_analysis_id, result_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
        (scan_type, target, status, vt_analysis_id, result_text)
    )
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    return rid

def get_scans(limit: int = 200) -> List[Dict[str, Any]]:
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, scan_type, target, status, vt_analysis_id, result_json, created_at, updated_at "
        "FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
    )
    rows = cur.fetchall()
    out = []
    for r in rows:
        parsed = None
        try:
            if r["result_json"]:
                parsed = json.loads(r["result_json"])
        except Exception:
            parsed = r["result_json"]
        out.append({
            "id": r["id"],
            "scan_type": r["scan_type"],
            "target": r["target"],
            "status": r["status"],
            "vt_analysis_id": r["vt_analysis_id"],
            "result_json": parsed,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        })
    conn.close()
    return out

def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, scan_type, target, status, vt_analysis_id, result_json, created_at, updated_at "
        "FROM scans WHERE id = ?", (scan_id,)
    )
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    parsed = None
    try:
        if r["result_json"]:
            parsed = json.loads(r["result_json"])
    except Exception:
        parsed = r["result_json"]
    return {
        "id": r["id"],
        "scan_type": r["scan_type"],
        "target": r["target"],
        "status": r["status"],
        "vt_analysis_id": r["vt_analysis_id"],
        "result_json": parsed,
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }

def clear_history() -> None:
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
