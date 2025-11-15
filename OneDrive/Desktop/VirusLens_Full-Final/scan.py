# scan.py
"""
DB-backed scan helpers for VirusLens.

Provides:
- init_db(db_path: Path | str | None) -> None
- get_db_path() -> pathlib.Path
- record_search(scan_type: str, input_value: str, summary: str = "", risk_score: str = "", vt_details: dict|None = None, db_path: Path|str|None = None) -> int
- list_scans(limit: int = 200, db_path: Path|str|None = None) -> list[dict]
- get_scan(scan_id: int, db_path: Path|str|None = None) -> dict|None

Notes:
- This module intentionally uses sqlite3 (std lib) for simplicity and portability.
- vt_details is JSON-serialized into the vt_details TEXT column for report extraction.
"""

from pathlib import Path
import sqlite3
import json
import datetime
import os
import sys
from typing import Optional, List, Dict, Any

# ---------- DB path helper -----------------------------------------------

def get_db_path() -> Path:
    """
    Locate viruslens.db file in a few common places.

    Search order:
      1. st.secrets["VL_DB_FILE"] if running under Streamlit (pages should pass db_path if they want a specific file)
      2. environment VL_DB_FILE
      3. cwd / viruslens.db
      4. project root ../viruslens.db (assumes this file is app/scan.py)
      5. app/viruslens.db
    """
    # Try environment first
    env_path = os.environ.get("VL_DB_FILE")
    if env_path:
        p = Path(env_path)
        return p

    # fallback candidate - project root / viruslens.db
    this_file = Path(__file__).resolve()
    # typical layout: project_root/app/scan.py -> project_root = parents[1]
    maybe_project_root = this_file.parents[1] if len(this_file.parents) >= 2 else this_file.parent

    candidates = [
        Path.cwd() / "viruslens.db",
        maybe_project_root / "viruslens.db",
        maybe_project_root / "app" / "viruslens.db",
        this_file.parent / "viruslens.db"
    ]
    for c in candidates:
        try:
            if c.exists():
                return c
        except Exception:
            # Continue if some path can't be checked
            continue

    # If none exist, return the project-root candidate (DB will be created when init_db called)
    return maybe_project_root / "viruslens.db"

# ---------- DB connection helpers ---------------------------------------

def _connect(db_path: Optional[Path | str]) -> sqlite3.Connection:
    """Return sqlite3 Connection; create parent dir if necessary."""
    if db_path is None:
        db_path = get_db_path()
    dbp = Path(db_path)
    if not dbp.parent.exists():
        try:
            dbp.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Failed to create DB directory {dbp.parent}: {e}", file=sys.stderr)
    conn = sqlite3.connect(str(dbp), detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- table creation / initialization -----------------------------

def init_db(db_path: Optional[Path | str] = None) -> None:
    """
    Ensure database exists and tables are present.
    Creates a simple 'scans' table suitable for recording scan events.
    """
    conn = _connect(db_path)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        input TEXT,
        scan_type TEXT,
        risk_score TEXT,
        summary TEXT,
        vt_details TEXT,           -- JSON blob for vendor details / extra structured data
        created_at TEXT DEFAULT (datetime('now'))
    )
    """)
    # For backwards compatibility some forks used a 'history' table; create if missing (safe)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        input_value TEXT,
        scan_type TEXT,
        risk_score TEXT,
        summary TEXT,
        timestamp TEXT DEFAULT (datetime('now'))
    )
    """)
    conn.commit()
    conn.close()

# ---------- record / list / fetch --------------------------------------

def record_search(
    scan_type: str,
    input_value: str,
    summary: str = "",
    risk_score: str = "",
    vt_details: Optional[Dict[str, Any]] = None,
    db_path: Optional[Path | str] = None
) -> int:
    """
    Record a completed scan/search into the DB.
    Returns the inserted scan id.

    Parameters:
    - scan_type: e.g. "url", "file", "csv"
    - input_value: the actual URL, file name, or query string
    - summary: short summary text
    - risk_score: textual or numeric risk indicator
    - vt_details: optional dict; will be JSON serialized to vt_details column
    """
    if input_value is None:
        input_value = ""

    vt_json = None
    if vt_details is not None:
        try:
            vt_json = json.dumps(vt_details, ensure_ascii=False)
        except Exception:
            try:
                # try a simple fallback
                vt_json = json.dumps(str(vt_details))
            except Exception:
                vt_json = None

    conn = _connect(db_path)
    cur = conn.cursor()
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cur.execute("""
            INSERT INTO scans (input, scan_type, risk_score, summary, vt_details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (input_value, scan_type, str(risk_score or ""), summary or "", vt_json, now))
        scan_id = cur.lastrowid
        # Also insert into history table (for forks/pages that look for it)
        try:
            cur.execute("""
                INSERT INTO history (input_value, scan_type, risk_score, summary, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (input_value, scan_type, str(risk_score or ""), summary or "", now))
        except Exception:
            # ignore history insertion failures
            pass
        conn.commit()
    except Exception as exc:
        conn.rollback()
        print(f"Failed to record scan to DB: {exc}", file=sys.stderr)
        raise
    finally:
        conn.close()

    return scan_id

def list_scans(limit: int = 200, db_path: Optional[Path | str] = None) -> List[Dict[str, Any]]:
    """
    Return recent scans as a list of dicts (most recent first).
    Each dict contains: id, input, type, risk, summary, timestamp, vt_details (dict or None).
    """
    conn = _connect(db_path)
    cur = conn.cursor()
    results = []
    # Prefer scans table
    try:
        cur.execute("""
            SELECT id, input, scan_type, risk_score, summary, vt_details, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        for r in rows:
            vt = None
            try:
                vt = json.loads(r["vt_details"]) if r["vt_details"] else None
            except Exception:
                vt = None
            results.append({
                "id": r["id"],
                "input": r["input"] or "",
                "type": r["scan_type"] or "",
                "risk": r["risk_score"] or "",
                "summary": r["summary"] or "",
                "timestamp": r["created_at"] or "",
                "vt_details": vt
            })
        conn.close()
        return results
    except Exception:
        # fallback: try to read history table if scans doesn't exist / has different schema
        try:
            cur.execute("""
                SELECT id, input_value, scan_type, risk_score, summary, timestamp
                FROM history
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            for r in rows:
                results.append({
                    "id": r["id"],
                    "input": r["input_value"] or "",
                    "type": r["scan_type"] or "",
                    "risk": r["risk_score"] or "",
                    "summary": r["summary"] or "",
                    "timestamp": r["timestamp"] or "",
                    "vt_details": None
                })
        except Exception:
            # final fallback: return empty list
            pass
        finally:
            conn.close()
        return results

def get_scan(scan_id: int, db_path: Optional[Path | str] = None) -> Optional[Dict[str, Any]]:
    """
    Return a single scan by id as a dict or None if not found.
    """
    conn = _connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, input, scan_type, risk_score, summary, vt_details, created_at
            FROM scans
            WHERE id = ?
            LIMIT 1
        """, (int(scan_id),))
        r = cur.fetchone()
        if not r:
            # try history table fallback
            cur.execute("""
                SELECT id, input_value, scan_type, risk_score, summary, timestamp
                FROM history
                WHERE id = ?
                LIMIT 1
            """, (int(scan_id),))
            r = cur.fetchone()
            if not r:
                return None
            return {
                "id": r["id"],
                "input": r["input_value"] or "",
                "type": r["scan_type"] or "",
                "risk": r["risk_score"] or "",
                "summary": r["summary"] or "",
                "timestamp": r["timestamp"] or "",
                "vt_details": None
            }

        vt = None
        try:
            vt = json.loads(r["vt_details"]) if r["vt_details"] else None
        except Exception:
            vt = None
        return {
            "id": r["id"],
            "input": r["input"] or "",
            "type": r["scan_type"] or "",
            "risk": r["risk_score"] or "",
            "summary": r["summary"] or "",
            "timestamp": r["created_at"] or "",
            "vt_details": vt
        }
    except Exception as exc:
        print(f"get_scan error: {exc}", file=sys.stderr)
        return None
    finally:
        conn.close()

# ---------- convenience / aliases --------------------------------------

def get_scans(limit: int = 200, db_path: Optional[Path | str] = None) -> List[Dict[str, Any]]:
    """Alias for list_scans; some pages import get_scans."""
    return list_scans(limit=limit, db_path=db_path)

def record_search_url(url: str, summary: str = "", risk_score: str = "", vt_details: Optional[Dict[str, Any]] = None, db_path: Optional[Path | str] = None) -> int:
    """Convenience wrapper for URL scans."""
    return record_search("url", input_value=url, summary=summary, risk_score=risk_score, vt_details=vt_details, db_path=db_path)


# ---------- simple self-test when run directly --------------------------

if __name__ == "__main__":
    # quick manual smoke-test
    p = get_db_path()
    print("DB path:", p)
    init_db(p)
    print("Inserting test record...")
    rid = record_search("url", "https://example.local/test", summary="Manual test", risk_score="Low", vt_details={"note": "test"})
    print("Inserted id:", rid)
    print("Recent scans:", list_scans(limit=10))
    print("Fetch scan:", get_scan(rid))
