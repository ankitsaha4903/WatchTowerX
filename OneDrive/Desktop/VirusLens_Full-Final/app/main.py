from __future__ import annotations

# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable
# IMPORT STREAMLIT AFTER sys.path guard and future imports
import streamlit as st

# --- IMPORTANT: set_page_config must be the first Streamlit command in this file ---
st.set_page_config(page_title="VirusLens — Scan", layout="wide")
# app/main.py

import json
import os
import time
from typing import Optional
# --- Robust import of DB helpers (main page) --------------------------------
# Try the original app.db exports first (keeps compatibility).
# If they are not present, fall back to the helpers from app.scan.
try:
    # preferred / original
    from app.db import record_search, get_history
except Exception:
    # fallback: some forks keep DB helpers in scan.py
    try:
        from app.scan import record_search, list_scans
    except Exception as e:
        # Last resort: give a helpful error (prevents obscure ImportError)
        raise ImportError(
            "Failed to import DB helpers. Expected either `app.db` to expose "
            "`record_search` and `get_history`, or `app.scan` to expose "
            "`record_search` and `list_scans`. Original error: " + str(e)
        )

    # provide a small compatibility wrapper so the rest of main.py can call get_history()
    def get_history(limit=200, *args, **kwargs):
        """
        Compatibility wrapper for older code that expects get_history(limit).
        list_scans(limit=...) returns a list of scan dicts.
        """
        # list_scans signature might be (limit=..., db_path=None), so pass through.
        return list_scans(limit=int(limit), *args, **kwargs)
# -----------------------------------------------------------------------------

import streamlit as st
from dotenv import load_dotenv

# Ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# import backend functions (scan.py must exist in project root)
try:
    from scan import (
        get_engine, init_db, perform_url_scan, perform_hash_lookup,
        list_scans, export_scans_csv, export_scan_pdf
    )
except Exception as e:
    st.error("Failed to import scan backend. Ensure scan.py exists in project root and is valid.")
    st.exception(e)
    raise

# load environment
load_dotenv(ROOT / ".env")

st.set_page_config(page_title="VirusLens — Scan", layout="wide")
st.title("VirusLens — Scanner")

# initialize DB lazily
_engine = None


def engine() -> "Engine":
    global _engine
    if _engine is None:
        _engine = get_engine()
        init_db(_engine)
    return _engine


# Sidebar: quick actions and info
with st.sidebar:
    st.header("Actions")
    st.write("Use the controls below to perform scans, lookup hashes, export results, and view reports.")
    if st.button("Refresh scans list"):
        st.experimental_rerun()

    st.markdown("---")
    st.subheader("Exports")
    if st.button("Export all scans to CSV"):
        try:
            out = export_scans_csv(engine())
            st.success(f"Exported CSV to: {out}")
            st.markdown(f"[Download CSV]({out})")
        except Exception as e:
            st.error("Export failed")
            st.exception(e)

    st.markdown("---")
    st.write("Environment")
    st.code(dict(os.environ), language="json")

# Main layout
col1, col2 = st.columns([2, 1])

with col1:
    st.header("Scan URL")
    url = st.text_input("Enter URL to scan (include protocol - http/https)", value="")
    poll = st.checkbox("Poll until analysis completes", value=True)
    timeout = st.number_input("Poll timeout (seconds)", min_value=10, value=180, step=10)
    submit_scan = st.button("Submit URL")
    record_search("url", url, summary="scan completed")

    if submit_scan:
        if not url:
            st.warning("Please enter a URL.")
        else:
            st.info("Submitting URL for analysis...")
            try:
                result = perform_url_scan(engine(), url, poll=poll, poll_timeout=timeout, poll_interval=5)
                st.success("Scan recorded.")
                st.write("Scan record:")
                st.json(result)
                # record in history
                summary = ""
                try:
                    # attempt to create a short summary (malicious stats or status)
                    if result and isinstance(result, dict):
                        # if result has result_json stored row, parse it
                        rj = result.get("result_json")
                        if isinstance(rj, str):
                            parsed = json.loads(rj) if rj else {}
                        else:
                            parsed = result.get("analysis") or result.get("initial_response") or {}
                        # try to find last_analysis_stats if present
                        stats = (parsed.get("data", {}) .get("attributes", {}) .get("last_analysis_stats", {}) ) if parsed else {}
                        if stats:
                            summary = json.dumps(stats)
                except Exception:
                    summary = ""
                record_search("url", url, summary=summary)
            except Exception as e:
                st.error("URL scan failed.")
                st.exception(e)
                # still record the attempted search
                record_search("url", url, summary=f"error: {str(e)}")


    st.markdown("---")
    st.header("Lookup File Hash")
    st.write("Enter a file hash (MD5 / SHA1 / SHA256) to lookup in VirusTotal")
    file_hash = st.text_input("File hash", value="")
    lookup_btn = st.button("Lookup hash")

    if lookup_btn:
        if not file_hash:
            st.warning("Please enter a hash.")
        else:
            with st.spinner("Looking up hash..."):
                try:
                    r = perform_hash_lookup(engine(), file_hash)
                    st.success("Lookup complete.")
                    st.json(r)
                    # store in history
                    record_search("hash", file_hash, summary="lookup_success")
                except Exception as e:
                    st.error("Hash lookup failed.")
                    st.exception(e)
                    record_search("hash", file_hash, summary=f"error: {str(e)}")


    st.markdown("---")
    st.header("Scan details")
    st.info("Select a scan from the right-hand table to view details and export to PDF/HTML.")

with col2:
    st.header("Saved Scans")
    # Pagination controls
    limit = st.number_input("Show most recent (limit)", min_value=1, max_value=1000, value=50, step=10)
    scans = list_scans(engine(), limit=limit)
    st.metric("Total saved scans (last limited shown)", len(scans))

    if not scans:
        st.warning("No scans found. Submit a scan to create results.")
    else:
        # Build a table view
        # Convert result_json to summarized string for table
        table_rows = []
        for s in scans:
            js = s.get("result_json") or ""
            short = ""
            if js:
                try:
                    parsed = json.loads(js)
                    # try to glean a short status or stats
                    attr = parsed.get("data", {}).get("attributes", {})
                    short = json.dumps({
                        k: attr.get(k) for k in ("status", "last_analysis_stats")
                        if attr.get(k) is not None
                    })
                except Exception:
                    short = js[:200].replace("\n", " ")
            table_rows.append({
                "id": s["id"],
                "type": s["scan_type"],
                "target": s["target"],
                "status": s["status"],
                "vt_analysis_id": s.get("vt_analysis_id") or "",
                "summary": short
            })

        import pandas as pd
        df = pd.DataFrame(table_rows)
        st.dataframe(df, use_container_width=True)

        st.markdown("### Select a scan")
        selected_id = st.number_input("Scan ID to view/export", min_value=1, value=int(scans[0]["id"]))
        if st.button("Load scan details"):
            try:
                from scan import get_scan  # lazy import to avoid circular issues
                scan_detail = get_scan(engine(), int(selected_id))
                if not scan_detail:
                    st.error("Scan ID not found.")
                else:
                    st.json(scan_detail)
            except Exception as e:
                st.error("Failed to load scan")
                st.exception(e)

        # Export selected scan to PDF or HTML
            if st.button("Export to PDF/HTML"):
                try:
                    out = export_scan_pdf(engine(), int(selected_id), out_path=(out_file or None))
                    st.success(f"Exported to: {out}")
                    st.markdown(f"[Open exported file]({out})")
                    record_search("export_pdf", f"scan:{selected_id}", summary=out)
                except Exception as e:
                    st.error("Export failed.")
                    st.exception(e)
                    record_search("export_pdf", f"scan:{selected_id}", summary=f"error: {str(e)}")


# Footer / diagnostics
st.markdown("---")
st.write("Notes:")
st.markdown("""
- The server-side scan functions use VirusTotal API. Put your `VIRUSTOTAL_API_KEY` into `.env`.  
- If you want to avoid hitting live APIs during development, set `MOCK_MODE=true` in `.env`.  
- Exported files are written under the project `exports/` directory by default.  
""")
