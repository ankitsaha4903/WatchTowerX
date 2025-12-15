import sqlite3
from config import DB_PATH

def migrate_devices():
    print("Starting devices table migration...")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    try:
        # Check if column exists
        cur.execute("PRAGMA table_info(devices)")
        columns = [col[1] for col in cur.fetchall()]
        
        if 'alias' not in columns:
            print("Adding 'alias' column to 'devices' table...")
            cur.execute("ALTER TABLE devices ADD COLUMN alias TEXT")
            conn.commit()
            print("✅ 'alias' column added successfully.")
        else:
            print("ℹ️ 'alias' column already exists.")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_devices()
