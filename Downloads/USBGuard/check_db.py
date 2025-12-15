import sqlite3
from config import DB_PATH

def check_schema():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("PRAGMA table_info(users)")
        columns = cur.fetchall()
        print("Current 'users' table columns:")
        for col in columns:
            print(f"- {col[1]} ({col[2]})")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_schema()
