# migrate_scans_table.py
"""
Standalone migration for viruslens.db scans table.
Run with: python migrate_scans_table.py
"""

import sqlite3
import sys
import os
from datetime import datetime

DB = os.getenv("VL_DB_FILE", "viruslens.db")

EXPECTED_COLUMNS = {
    "id": "INTEGER",
    "scan_type": "VARCHAR(32)",
    "target": "VARCHAR(1024)",
    "status": "VARCHAR(32)",
    "vt_analysis_id": "VARCHAR(256)",
    "result_json": "TEXT",
    "created_at": "DATETIME",
    "updated_at": "DATETIME",
}

def connect(db_path):
    if not os.path.exists(db_path):
        print(f"Database file not found: {db_path}")
        sys.exit(1)
    return sqlite3.connect(db_path)

def get_columns(conn):
    cur = conn.execute("PRAGMA table_info(scans)")
    rows = cur.fetchall()
    # rows: (cid, name, type, notnull, dflt_value, pk)
    return {r[1]: r for r in rows}

def add_column(conn, col, ctype):
    # choose default appropriate for column
    if col in ("created_at", "updated_at"):
        default = "CURRENT_TIMESTAMP"
    elif col == "scan_type":
        default = "'url'"
    elif col == "status":
        default = "'queued'"
    elif col == "target":
        default = "''"
    else:
        default = "NULL"

    sql = f"ALTER TABLE scans ADD COLUMN {col} {ctype} DEFAULT {default}"
    print("Executing:", sql)
    conn.execute(sql)

def safe_migrate(db_path):
    conn = connect(db_path)
    try:
        cols = get_columns(conn)
        if not cols:
            print("No 'scans' table found. Creating new scans table.")
            # create new table
            create_sql = """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type VARCHAR(32) DEFAULT 'url',
                target VARCHAR(1024) DEFAULT '',
                status VARCHAR(32) DEFAULT 'queued',
                vt_analysis_id VARCHAR(256),
                result_json TEXT,
                created_at DATETIME DEFAULT (CURRENT_TIMESTAMP),
                updated_at DATETIME DEFAULT (CURRENT_TIMESTAMP)
            );
            """
            conn.executescript(create_sql)
            conn.commit()
            print("Created scans table.")
            cols = get_columns(conn)

        # determine missing columns
        missing = [c for c in EXPECTED_COLUMNS.keys() if c not in cols]
        if not missing:
            print("All expected columns already present:", list(cols.keys()))
        else:
            print("Missing columns detected:", missing)
            # add columns one by one
            for c in missing:
                try:
                    add_column(conn, c, EXPECTED_COLUMNS[c])
                    conn.commit()
                    print(f"Added column: {c}")
                except Exception as e:
                    print(f"Failed to add column {c}: {e}")
                    # don't abort yet; try next
            print("Migration pass complete.")

        # verify final schema
        final = get_columns(conn)
        print("Final scans table columns:")
        for name, row in final.items():
            print(" -", name, "type:", row[2], "default:", row[4])
    finally:
        conn.close()

if __name__ == "__main__":
    print("Starting migration at", datetime.utcnow().isoformat())
    safe_migrate(DB)
    print("Migration finished")
