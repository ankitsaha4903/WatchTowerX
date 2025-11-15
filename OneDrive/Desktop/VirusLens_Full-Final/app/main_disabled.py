# app/pages/00_Main.py
# HEADLESS stub for "Main" page:
# - ensures backend modules are imported / initialized
# - immediately stops the Streamlit script so nothing is rendered
# - keeps st.set_page_config as the first Streamlit call

import streamlit as st

# NOTE: st.set_page_config must be the first Streamlit call in the file.
st.set_page_config(page_title="(hidden) Main", layout="wide")

# Import backend modules here so their module-level initialization still runs.
# Wrap imports in try/except to avoid breaking the page if names changed.
# Adjust names if your backend modules live elsewhere (e.g. app.scan, app.db)
_import_errors = []
try:
    # attempt to import the functions/modules your app uses
    # prefer specific imports to avoid circular import surprises
    from app import scan as _scan  # keeps scan.py side-effects (init) running
except Exception as e:
    _import_errors.append(("app.scan", str(e)))

try:
    from app import db as _db  # if you have app/db.py with functions
except Exception as e:
    _import_errors.append(("app.db", str(e)))

# If your project defines init_db/get_db_path/record_search/list_scans in a module named "scan.py"
# you can try specific safe calls to initialize DB without UI noise:
try:
    if hasattr(_scan, "init_db"):
        # don't crash if this fails; just best-effort initialization
        try:
            # call with no args (scan.init_db should pick default DB path)
            _scan.init_db()
        except TypeError:
            # some versions accept a path argument; ignore if signature differs
            pass
except Exception:
    pass

# If you want to surface import issues in logs (optional), you can print them:
if _import_errors:
    # Put errors in the server log (not the UI) for debugging
    import logging
    logging.getLogger("viruslens").warning("Main-page import problems: %s", _import_errors)

# Stop here so Streamlit shows nothing for this page.
# This effectively hides the Main page from the UI while keeping backend init in place.
st.stop()
