# ==========================
# 🧬 VIRUSLENS MAIN MODULE
# ==========================

import os
import sys
import time
import requests
from dotenv import load_dotenv
import streamlit as st
from pathlib import Path
import socket

# Get current running port dynamically
def get_current_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port
# app/main.py (at the very top, after imports)
from app.utils.ui import setup_page, apply_theme

setup_page("VirusLens — Cyber Threat Analyzer")   # FIRST Streamlit call
apply_theme()                                     # inject CSS after config


st.sidebar.info(f"🧩 VirusLens is running securely on a random port each time (HTTPS enabled).")


# ---- Fix import paths ----
CURRENT_DIR = Path(__file__).parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---- Load API key ----
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ---- Page Setup ----
APP_DIR = Path(__file__).parent
ICON_PATH = APP_DIR / "assets" / "icon.png"

st.set_page_config(
    page_title="VirusLens | Advanced Threat Intelligence",
    page_icon="🧬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---- Branding Header ----
st.markdown(
    """
    <style>
    .title {
        font-size: 42px;
        font-weight: 800;
        color: #00E5FF;
        text-shadow: 0px 0px 12px #00E5FFAA;
    }
    .subtitle {
        font-size: 18px;
        color: #AAAAAA;
    }
    </style>
    <div class='title'>🧬 VirusLens</div>
    <div class='subtitle'>
        Next-Generation Threat Analyzer powered by VirusTotal API.
    </div>
    """,
    unsafe_allow_html=True
)

# ---- Sidebar ----
st.sidebar.title("🧠 About VirusLens")
st.sidebar.info(
    """
    **VirusLens** analyzes URLs and file hashes through the VirusTotal v3 API.  
    Built for researchers and cybersecurity students.  
    Use responsibly and respect API limits.  

    **Stack:** Python | Streamlit | VirusTotal API | SQLite
    """
)
st.sidebar.caption("©VirusLens – Cyber Security Project")

# ==============================================================
# 🧩 URL Scanner Section
# ==============================================================

st.markdown("## 🌐 URL Scanner")

url_input = st.text_input("Enter a URL to scan:", placeholder="https://example.com")
poll_timeout = st.slider("Polling timeout (seconds)", 5, 60, 20)

if st.button("🔍 Scan URL"):
    if not VT_API_KEY:
        st.error("⚠️ VirusTotal API key not found. Please add it in your `.env` file as `VIRUSTOTAL_API_KEY=YOUR_KEY`.")
    elif not url_input:
        st.warning("Please enter a URL before scanning.")
    else:
        try:
            with st.spinner("Submitting URL to VirusTotal..."):
                headers = {"x-apikey": VT_API_KEY}
                data = {"url": url_input}
                res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

                if res.status_code != 200:
                    st.error(f"❌ VirusTotal Error: {res.status_code} - {res.text}")
                else:
                    analysis_id = res.json()["data"]["id"]

                    # Polling for report
                    with st.spinner("Analyzing... this may take a few seconds"):
                        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

                        for _ in range(poll_timeout):
                            report_res = requests.get(report_url, headers=headers)
                            report_data = report_res.json()
                            status = report_data["data"]["attributes"]["status"]

                            if status == "completed":
                                break
                            time.sleep(1)

                    # Parse final report
                    stats = report_data["data"]["attributes"]["stats"]
                    harmless = stats.get("harmless", 0)
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)

                    st.success("✅ Analysis Complete!")

                    # Display results
                    st.write("### 🧾 Threat Summary")
                    st.write(f"**Harmless:** {harmless}")
                    st.write(f"**Malicious:** {malicious}")
                    st.write(f"**Suspicious:** {suspicious}")
                    st.write(f"**Undetected:** {undetected}")

                    vt_url_id = report_data["meta"]["url_info"]["id"]
                    vt_link = f"https://www.virustotal.com/gui/url/{vt_url_id}"
                    st.markdown(f"[🔗 View Full Report on VirusTotal]({vt_link})")

        except Exception as e:
            st.error(f"⚠️ Unexpected error: {e}")
