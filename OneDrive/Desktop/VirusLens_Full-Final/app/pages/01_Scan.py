from __future__ import annotations

# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

# app/pages/01_Scan.py
import io
import json
import streamlit as st

from app.utils.ui import setup_page, apply_theme
from app.utils.paths import ensure_dirs
from app.utils.engines import aggregate_scan, detect_ioc_type, sha256_file
from app.utils.virustotal import file_hash_sha256  # if you prefer the older helper
from app.utils.secrets import get_vt_api_key

setup_page("VirusLens — Cyber Threat Analyzer")
apply_theme()
ensure_dirs()

st.markdown("### 🛡️ VirusLens — Cyber Threat Analyzer")
st.caption("Scan a URL or upload a file. API keys are read from the backend configuration.")

left, right = st.columns(2)

with left:
    st.subheader("Scan URL")
    url = st.text_input("Enter URL", placeholder="https://example.com")
    btn_url = st.button("Scan URL")

with right:
    st.subheader("Scan File")
    up = st.file_uploader("Upload a file", type=None)
    btn_file = st.button("Scan File")

# Check API key early so the UX is clear
try:
    _ = get_vt_api_key()
except Exception as e:
    st.error(str(e))
    st.stop()

def render_result(res: dict):
    st.success(f"Overall risk: **{res['overall_risk']}**  •  Type: `{res['type']}`")
    for eng in res["engines"]:
        with st.expander(f"Details — {eng.get('engine','?')}"):
            st.json(eng.get("summary", {}))

if btn_url and url:
    with st.spinner("Scanning URL…"):
        try:
            res = aggregate_scan(url, "url")
            render_result(res)
        except Exception as e:
            st.error(f"Scan failed: {e}")

if btn_file and up is not None:
    with st.spinner("Hashing and checking file…"):
        try:
            # Save to temp buffer and hash
            b = up.read()
            h = file_hash_sha256  # keep compatibility with your existing helper
            sha = h(io.BytesIO(b)) if callable(h) and h.__code__.co_argcount == 1 else None
            # if the older helper expects a path, compute here quickly
            if sha is None:
                import hashlib
                hh = hashlib.sha256(); hh.update(b); sha = hh.hexdigest()
            res = aggregate_scan(sha, "hash")
            render_result(res)
        except Exception as e:
            st.error(f"Scan failed: {e}")
