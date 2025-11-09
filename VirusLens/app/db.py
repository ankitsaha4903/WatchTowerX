from sqlalchemy import create_engine, text
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "vt_results.db"
DB_URI = f"sqlite:///{DB_PATH}"

engine = create_engine(DB_URI, echo=False, future=True)

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_type TEXT NOT NULL,        -- 'url' or 'hash'
            input_value TEXT NOT NULL,
            verdict TEXT,
            malicious INTEGER,
            suspicious INTEGER,
            harmless INTEGER,
            undetected INTEGER,
            timeout INTEGER,
            vt_link TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """))

def insert_scan(row: dict):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO scans (
                input_type,input_value,verdict,malicious,suspicious,harmless,undetected,timeout,vt_link
            ) VALUES (
                :input_type,:input_value,:verdict,:malicious,:suspicious,:harmless,:undetected,:timeout,:vt_link
            );
        """), row)

def fetch_recent(limit: int = 50):
    with engine.begin() as conn:
        res = conn.execute(text("""
            SELECT id,input_type,input_value,verdict,malicious,suspicious,harmless,undetected,timeout,vt_link,created_at
            FROM scans ORDER BY id DESC LIMIT :limit
        """), {"limit": limit}).mappings().all()
    return [dict(r) for r in res]
