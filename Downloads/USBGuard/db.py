# db.py

import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from config import DB_PATH, DEFAULT_POLICIES


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # Devices table
    # Note: We are keeping mount_point UNIQUE for now to avoid schema migration issues,
    # but we will handle it in upsert_device.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mount_point TEXT UNIQUE,
        device_id TEXT,
        vendor TEXT,
        product TEXT,
        first_seen TEXT,
        last_seen TEXT,
        status TEXT,      -- allowed, blocked, unknown, pending_approval
        last_action TEXT  -- allowed, blocked, read_only, whitelisted, etc.
    );
    """)

    # Logs table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        event_type TEXT,
        username TEXT,
        device_id TEXT,
        mount_point TEXT,
        message TEXT
    );
    """)

    # Sensitive paths (folders you consider confidential)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sensitive_paths (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT UNIQUE
    );
    """)

    # Sensitive keywords for DLP
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sensitive_keywords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        keyword TEXT UNIQUE
    );
    """)

    # Sensitive Regex for Advanced DLP
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sensitive_regex (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE,
        description TEXT
    );
    """)

    # Users table for Authentication (enhanced for multiple auth methods)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        email TEXT UNIQUE,
        phone_number TEXT UNIQUE,
        auth_method TEXT DEFAULT 'password',
        google_id TEXT UNIQUE,
        device_type TEXT,
        model_name TEXT,
        email_verified INTEGER DEFAULT 0,
        phone_verified INTEGER DEFAULT 0,
        created_at TEXT
    );
    """)

    # Policies table (key-value)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)

    # Seed default policies if not present
    for key, value in DEFAULT_POLICIES.items():
        cur.execute("""
        INSERT OR IGNORE INTO policies (key, value)
        VALUES (?, ?);
        """, (key, value))

    # Seed default admin user if not present
    cur.execute("SELECT count(*) as c FROM users;")
    if cur.fetchone()['c'] == 0:
        # Default: admin / admin123
        p_hash = generate_password_hash("admin123")
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?);", ("admin", p_hash))
        print("[DB] Default admin user created (admin/admin123).")

    conn.commit()
    conn.close()


def log_event(level: str, event_type: str, message: str,
              username: str = "", device_id: str = "", mount_point: str = ""):
    conn = get_connection()
    cur = conn.cursor()
    ts = datetime.utcnow().isoformat()
    cur.execute("""
    INSERT INTO logs (timestamp, level, event_type, username, device_id, mount_point, message)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (ts, level, event_type, username, device_id, mount_point, message))
    conn.commit()
    conn.close()


def upsert_device(mount_point: str, device_id: str, vendor: str, product: str):
    """
    Insert or update a device row. 
    Uses device_id as the unique identifier for the device itself.
    """
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    
    # Check if device exists by device_id
    cur.execute("SELECT * FROM devices WHERE device_id = ?;", (device_id,))
    row = cur.fetchone()
    
    if row:
        # Update existing device
        cur.execute("""
        UPDATE devices 
        SET mount_point = ?, vendor = ?, product = ?, last_seen = ?
        WHERE device_id = ?;
        """, (mount_point, vendor, product, now, device_id))
    else:
        # Insert new device
        # Handle potential mount_point conflict by clearing it from other devices
        cur.execute("UPDATE devices SET mount_point = '' WHERE mount_point = ?;", (mount_point,))
        
        # New devices default to 'pending_approval' instead of 'unknown'
        cur.execute("""
        INSERT INTO devices (mount_point, device_id, vendor, product, first_seen, last_seen, status, last_action)
        VALUES (?, ?, ?, ?, ?, ?, 'pending_approval', '')
        """, (mount_point, device_id, vendor, product, now, now))
        
    conn.commit()
    conn.close()


def update_device_status(mount_point: str, status: str, last_action: str = ""):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("""
    UPDATE devices
    SET status = ?, last_action = ?, last_seen = ?
    WHERE mount_point = ?;
    """, (status, last_action, now, mount_point))
    conn.commit()
    conn.close()


def get_device_by_mount(mount_point: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE mount_point = ?;", (mount_point,))
    row = cur.fetchone()
    conn.close()
    return row


def get_device_by_id(device_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = ?;", (device_id,))
    row = cur.fetchone()
    conn.close()
    return row


def set_device_status_by_id(device_id: int, status: str, last_action: str = ""):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("""
    UPDATE devices
    SET status = ?, last_action = ?, last_seen = ?
    WHERE id = ?;
    """, (status, last_action, now, device_id))
    conn.commit()
    conn.close()


def update_device_alias(device_id: int, alias: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET alias = ? WHERE id = ?;", (alias, device_id))
    conn.commit()
    conn.close()


def delete_device(device_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM devices WHERE id = ?;", (device_id,))
    conn.commit()
    conn.close()


def get_policies() -> Dict[str, str]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM policies;")
    rows = cur.fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}


def set_policy(key: str, value: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO policies (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
    """, (key, value))
    conn.commit()
    conn.close()


def get_sensitive_paths() -> List[str]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT path FROM sensitive_paths;")
    rows = cur.fetchall()
    conn.close()
    return [row["path"] for row in rows]


def get_sensitive_keywords() -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sensitive_keywords;")
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_sensitive_keyword(keyword: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO sensitive_keywords (keyword) VALUES (?);", (keyword,))
    conn.commit()
    conn.close()


def delete_sensitive_keyword(keyword_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM sensitive_keywords WHERE id=?;", (keyword_id,))
    conn.commit()
    conn.close()


# --- Regex Management ---
def get_sensitive_regex() -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sensitive_regex;")
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_sensitive_regex(pattern: str, description: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO sensitive_regex (pattern, description) VALUES (?, ?);", (pattern, description))
    conn.commit()
    conn.close()


def delete_sensitive_regex(regex_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM sensitive_regex WHERE id=?;", (regex_id,))
    conn.commit()
    conn.close()


# --- User Management ---
def get_user_by_username(username: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?;", (username,))
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_id(user_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def create_user(username: str = None, password: str = None, email: str = None, 
                phone_number: str = None, auth_method: str = 'password', google_id: str = None,
                device_type: str = None, model_name: str = None):
    """Create a new user with support for multiple authentication methods"""
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    
    p_hash = generate_password_hash(password) if password else None
    
    try:
        cur.execute("""
        INSERT INTO users (username, password_hash, email, phone_number, auth_method, 
                          google_id, device_type, model_name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (username, p_hash, email, phone_number, auth_method, google_id, device_type, model_name, now))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email address"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?;", (email,))
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_phone(phone_number: str) -> Optional[Dict[str, Any]]:
    """Get user by phone number"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE phone_number = ?;", (phone_number,))
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_google_id(google_id: str) -> Optional[Dict[str, Any]]:
    """Get user by Google ID"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE google_id = ?;", (google_id,))
    row = cur.fetchone()
    conn.close()
    return row


def verify_email(user_id: int):
    """Mark user's email as verified"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET email_verified = 1 WHERE id = ?;", (user_id,))
    conn.commit()
    conn.close()


def verify_phone(user_id: int):
    """Mark user's phone as verified"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET phone_verified = 1 WHERE id = ?;", (user_id,))
    conn.commit()
    conn.close()


def check_user_password(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = get_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        return user
    return None
