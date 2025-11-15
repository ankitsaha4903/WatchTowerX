# app/utils/ui.py
from __future__ import annotations
import streamlit as st

DARK_BG = "#0b1220"
DARK_PANEL = "#0f1a2b"
ACCENT = "#2bd1c8"
TEXT = "#e9eef6"
TEXT_MUTED = "#a7b3c6"

def setup_page(title: str = "VirusLens — Cyber Threat Analyzer") -> None:
    """Must be the first Streamlit call on every page."""
    st.set_page_config(
        page_title=title,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

def apply_theme(title_note: str = "VirusLens • Cyber Threat Analyzer") -> None:
    """Injects cross-platform CSS (desktop + mobile)."""
    st.markdown(
        f"""
        <style>
        /* ======= Base layout ======= */
        .block-container {{
            max-width: 1100px;
            padding-top: 1rem;
            padding-bottom: 2rem;
            margin-left: auto !important;
            margin-right: auto !important;
        }}
        html, body, [data-testid="stAppViewContainer"] {{
            background: {DARK_BG};
        }}
        header[data-testid="stHeader"] {{ background: transparent; }}

        /* ======= Sidebar ======= */
        [data-testid="stSidebar"] {{
            background: {DARK_PANEL};
            width: 240px !important;
        }}
        [data-testid="stSidebar"] * {{ color: {TEXT}; }}

        /* ======= Typography ======= */
        h1, h2, h3, h4 {{ color: {TEXT}; }}
        h1 {{ font-size: 2rem; line-height: 1.2; }}
        h2 {{ font-size: 1.25rem; color: {TEXT}; }}
        p, .stMarkdown, .stText, label, span {{ color: {TEXT_MUTED}; }}

        /* ======= Inputs & buttons ======= */
        .stSelectbox, .stTextInput, .stFileUploader, .stNumberInput {{ max-width: 840px; }}
        .stButton > button {{
            background: #11323a;
            color: {TEXT};
            border: 1px solid {ACCENT}44;
        }}
        .stButton > button:hover {{
            border-color: {ACCENT};
            box-shadow: 0 0 12px {ACCENT}44;
        }}

        /* ======= Small screens (Android/iOS) ======= */
        @media (max-width: 900px) {{
            .block-container {{ max-width: 96vw; padding-top: 0.5rem; }}
            h1 {{ font-size: 1.5rem; }}
            h2 {{ font-size: 1.1rem; }}
            .stSelectbox, .stTextInput, .stFileUploader, .stNumberInput {{ max-width: 100%; }}
            .stButton > button {{ width: 100%; }}
            [data-testid="stSidebar"] {{ width: 220px !important; }}
        }}
        @media (max-height: 820px) {{
            .block-container {{ padding-top: 0.5rem; }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""<div style="text-align:right;color:{TEXT_MUTED};font-size:.8rem;opacity:.85">
        {title_note}
        </div>""",
        unsafe_allow_html=True,
    )
