import sqlite3
from config import DB_PATH

def migrate_database():
    print("Starting database migration...")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    try:
        # 1. Rename existing table
        print("Renaming 'users' to 'users_old'...")
        cur.execute("ALTER TABLE users RENAME TO users_old")
        
        # 2. Create new table with correct schema
        print("Creating new 'users' table...")
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
        
        # 3. Copy data
        print("Copying existing data...")
        # We only have username and password_hash in the old table
        cur.execute("""
        INSERT INTO users (id, username, password_hash, auth_method)
        SELECT id, username, password_hash, 'password'
        FROM users_old
        """)
        
        # 4. Drop old table
        print("Dropping 'users_old'...")
        cur.execute("DROP TABLE users_old")
        
        conn.commit()
        print("✅ Migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
