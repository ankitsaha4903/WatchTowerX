# app/pages/06_About.py
"""
About page for VirusLens — Cyber Threat Analyzer.

This page intentionally shows only:
- About VirusLens
- What this website does
- Key features

All other sections removed per request.
"""

from __future__ import annotations

import streamlit as st
from pathlib import Path
import os

st.title("About VirusLens")

# Short description
st.markdown(
    """
VirusLens is a lightweight **Cyber Threat Analyzer** template built with Streamlit.
It integrates local persistence, VirusTotal lookups, hash lookups, URL scanning submissions,
and export features (CSV / PDF). This page explains what the app does and its core features.
"""
)

# -----------------------------
# What this website does
# -----------------------------
st.header("What this website does")
st.markdown(
    """
- **URL scanning** — submit a URL to VirusTotal (v3) for analysis and optionally poll until results are ready.  
- **Hash lookup** — query VirusTotal for an existing file hash (MD5 / SHA1 / SHA256) to view the last analysis.  
- **History / Audit** — every search/operation performed in the UI is recorded (type, query, summary, timestamp).  
- **Exports** — saved scans can be exported to CSV, and individual scan details can be exported to PDF (or an HTML fallback).  
- **Bulk operations** — support for doing batch or bulk scanning flows (if enabled in the UI).  
- **Mock mode** — a local testing mode that returns deterministic mock responses so you can develop without hitting API rate limits.  
"""
)

# -----------------------------
# Key features
# -----------------------------
st.header("Key features")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**Persistence**")
    st.write("All scans and history are stored in a local SQLite database (`viruslens.db`).")

with col2:
    st.markdown("**Exporting**")
    st.write("Quick export to CSV for all scans. Per-scan PDF/HTML export is available.")

with col3:
    st.markdown("**Safe development**")
    st.write("Set `MOCK_MODE=true` in `.env` to avoid hitting live APIs while developing.")
