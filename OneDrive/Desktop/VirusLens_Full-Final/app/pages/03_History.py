# app/pages/03_History.py
"""
History page - lists recent scans recorded in the local DB.

This file expects the following functions to be available from app/scan.py:
  - get_db_path()
  - init_db(db_path=None)
  - list_scans(limit=200, db_path=None)

If your scan module is in a different place adjust the import accordingly.
"""
from pathlib import Path
import streamlit as st
from typing import List, Dict, Any

# Import DB helpers from scan.py
# ensure scan.py is in the python path or same package (app/scan.py recommended)
try:
    from scan import get_db_path, init_db, list_scans
except Exception as e:
    # Provide a helpful message if import fails
    st.error(f"Failed to import DB helpers from scan.py: {e}")
    raise

# Page config (optional - ensure this is not repeated elsewhere)
st.set_page_config(page_title="History", layout="wide")

st.title("History")
st.write("All searches performed through the web UI are recorded here (URL scans, file scans, etc.).")

# Controls
limit = st.number_input("Limit", min_value=1, max_value=10000, value=200, step=10)
if "history_refresh" not in st.session_state:
    st.session_state.history_refresh = 0

col1, col2 = st.columns([1, 6])
with col1:
    if st.button("Refresh"):
        st.session_state.history_refresh += 1

with col2:
    st.markdown("")  # spacing

# Initialize DB (safe, idempotent)
try:
    db_path = get_db_path()
    # init_db will create file/tables if missing; pass the path so it's deterministic
    init_db(db_path)
except Exception as e:
    st.error(f"Failed to initialize DB at expected path: {e}")
    st.stop()

# Read recent scans
scans: List[Dict[str, Any]] = []
try:
    scans = list_scans(limit=int(limit), db_path=db_path)
except Exception as e:
    st.error(f"Failed to read scans from DB ({db_path}): {e}")
    st.stop()

# Optional: Clear history (dangerous, show confirm)
def _clear_history():
    import sqlite3
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        # Truncate both common tables if they exist
        try:
            cur.execute("DELETE FROM scans;")
        except Exception:
            pass
        try:
            cur.execute("DELETE FROM history;")
        except Exception:
            pass
        conn.commit()
        conn.close()
        st.success("History cleared.")
    except Exception as ex:
        st.error(f"Failed to clear history: {ex}")

with st.expander("History controls"):
    st.write("Adjust limit and refresh/clear history.")
    if st.button("Clear history"):
        if st.confirm("Are you sure you want to permanently clear the stored history?"):
            _clear_history()
            st.session_state.history_refresh += 1

# If no scans found, show info
if not scans:
    st.info("No URL scan history entries found.")
    st.stop()

# Display the count
st.markdown(f"**Entries found:** {len(scans)} (showing up to {limit})")

# Render a simple table: id | input | type | risk | summary | timestamp
table_rows = []
for s in scans:
    # ensure keys exist regardless of source table
    sid = s.get("id", "")
    inp = s.get("input", s.get("input_value", "")) or ""
    typ = s.get("type", s.get("scan_type", "")) or ""
    risk = s.get("risk", "")
    summary = s.get("summary", "")
    ts = s.get("timestamp", "") or s.get("created_at", "")
    table_rows.append({
        "Scan ID": sid,
        "Input": inp,
        "Type": typ,
        "Risk": risk,
        "Summary": summary,
        "Timestamp (UTC)": ts
    })

# Streamlit can display a list-of-dicts as a dataframe-like table
import pandas as pd
df = pd.DataFrame(table_rows)
st.dataframe(df, use_container_width=True)

# Optionally, allow the user to expand a single record for details
st.markdown("---")
st.subheader("Details")
sel = st.selectbox("Select scan (by id) to view full details", options=[r["Scan ID"] for r in table_rows], format_func=lambda v: f"Scan {v}" if v is not None else "(none)")

if sel is not None:
    # find object
    found = next((x for x in scans if x.get("id") == sel or str(x.get("id")) == str(sel)), None)
    if found:
        st.json(found)
    else:
        st.warning("Selected scan not found in the recent fetch — try Refresh.")
