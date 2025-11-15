# app/utils/secrets.py
from __future__ import annotations
import os

# Load .env once (quietly)
_ENV_LOADED = False
def _ensure_dotenv_loaded() -> None:
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    try:
        from dotenv import load_dotenv  # type: ignore
        # Do not override existing env; just add from .env if present
        load_dotenv(override=False)
    except Exception:
        pass
    _ENV_LOADED = True


def get_vt_api_key() -> str:
    """
    Resolve VirusTotal API key without surfacing Streamlit 'No secrets found' errors.

    Priority:
      1) Environment / .env: VIRUSTOTAL_API_KEY
      2) streamlit secrets: st.secrets["VIRUSTOTAL_API_KEY"]
    """
    _ensure_dotenv_loaded()

    # 1) ENV / .env
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if key:
        return key

    # 2) streamlit secrets (swallow any error if secrets.toml is missing)
    try:
        import streamlit as st  # type: ignore
        try:
            k = st.secrets["VIRUSTOTAL_API_KEY"]  # may raise if not present
            if k:
                return str(k)
        except Exception:
            pass
    except Exception:
        pass

    # Nothing found
    raise ValueError(
        "VirusTotal API key not found. Set VIRUSTOTAL_API_KEY in your environment or .env "
        "file, or add VIRUSTOTAL_API_KEY to Streamlit secrets."
    )
