# app/pages/04_Reports.py
"""
Reports page for VirusLens.
- Shows recent scans from the local DB
- Lets the user select a scan and generate a PDF report matching the layout/format of report_14.pdf
- All content placed inside tables (no raw JSON section)
Notes:
- st.set_page_config MUST be the first Streamlit command in this file.
- The file locates a viruslens.db via st.secrets["VL_DB_FILE"], ENV VL_DB_FILE, or common paths.
"""

from pathlib import Path
import os
import io
import sqlite3
import datetime
import json

import streamlit as st

# -------------- Streamlit page config (must be the first Streamlit command) --------------
st.set_page_config(page_title="Reports", layout="wide")

# -------------- PDF libraries --------------
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from scan import init_db, list_scans
# ---------------------------
# Utilities
# ---------------------------
# Robust rerun helper (works across Streamlit versions)
def safe_rerun():
    """
    Attempt to cause the Streamlit script to rerun. Tries multiple strategies
    to be compatible with different Streamlit releases:
      1) st.experimental_rerun() if present
      2) raise runtime.scriptrunner.RerunException
      3) raise streamlit.report_thread.RerunException (old)
      4) fallback: show an info asking user to refresh
    """
    # 1) public API if present
    try:
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
            return
    except Exception:
        # ignore and continue to other strategies
        pass

    # 2) runtime.scriptrunner.RerunException (newer versions)
    try:
        from streamlit.runtime.scriptrunner import RerunException
        raise RerunException()
    except Exception:
        pass

    # 3) older API location
    try:
        from streamlit.report_thread import RerunException
        raise RerunException()
    except Exception:
        pass

    # 4) last resort: instruct the user to refresh
    try:
        st.info("Please refresh the page to see the latest data.")
    except Exception:
        # nothing more to do
        pass

def get_db_path() -> Path:
    """
    Locate the viruslens sqlite DB file robustly.
    Search order:
      1. st.secrets["VL_DB_FILE"] (if available)
      2. ENV VL_DB_FILE
      3. current working dir ./viruslens.db
      4. project root (parent of app/) ../viruslens.db
      5. app subfolder ./app/viruslens.db
    Returns a Path (may not exist).
    """
    # 1) st.secrets if available (guarded)
    secret_path = None
    try:
        if hasattr(st, "secrets") and st.secrets:
            # st.secrets may be a SecretsSingleton or dict-like
            try:
                secret_path = st.secrets.get("VL_DB_FILE")
            except Exception:
                # fallback - try attribute-like access
                secret_path = None
    except Exception:
        secret_path = None

    # 2) environment variable
    env_path = os.environ.get("VL_DB_FILE")

    candidates = []
    if secret_path:
        candidates.append(Path(secret_path))
    if env_path:
        candidates.append(Path(env_path))

    # cwd
    candidates.append(Path.cwd() / "viruslens.db")

    # project root (assume this file is app/pages/04_Reports.py)
    this_file = Path(__file__).resolve()
    maybe_project_root = this_file.parents[2] if len(this_file.parents) >= 3 else this_file.parent
    candidates.append(maybe_project_root / "viruslens.db")
    # app/ subfolder
    candidates.append(maybe_project_root / "app" / "viruslens.db")
    # local folder (rare)
    candidates.append(this_file.parent / "viruslens.db")

    # Return first existing file; if none exist return the canonical project root candidate
    for p in candidates:
        try:
            if p.exists() and p.is_file():
                return p
        except Exception:
            continue
    return maybe_project_root / "viruslens.db"


def fetch_rows_from_db(db_path: Path, limit: int = 200):
    """
    Fetch recent scans from the DB using several fallback queries.
    Returns list[dict] sorted newest-first. If DB missing or unreadable -> [].
    Each dict keys: id, input, type, risk, summary, timestamp, vt_details (optional dict)
    """
    out = []
    if not db_path:
        return out
    if not db_path.exists():
        return out

    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()

        # 1) Try 'history' table
        try:
            cur.execute("""
                SELECT id,
                       COALESCE(input_value, input, target, '') AS input_val,
                       COALESCE(scan_type, type, '') AS scan_type,
                       COALESCE(risk_score, status, '') AS risk,
                       COALESCE(summary, result_json, '') AS summary,
                       COALESCE(timestamp, created_at, updated_at, '') AS ts
                FROM history
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            if rows:
                for r in rows:
                    out.append({
                        "id": r[0],
                        "input": r[1],
                        "type": r[2],
                        "risk": r[3],
                        "summary": r[4],
                        "timestamp": r[5],
                        "vt_details": {}  # placeholder
                    })
                conn.close()
                return out
        except Exception:
            pass

        # 2) Try 'scans' table
        try:
            cur.execute("""
                SELECT id,
                       COALESCE(target, input, '') as input_val,
                       COALESCE(scan_type, type, '') as scan_type,
                       COALESCE(status, '') as status,
                       COALESCE(result_json, '') as result_json,
                       COALESCE(created_at, updated_at, '') as ts
                FROM scans
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            if rows:
                for r in rows:
                    # attempt to parse JSON summary field if it's JSON and contains details
                    vt_details = {}
                    summary_field = r[4] or ""
                    try:
                        parsed = json.loads(summary_field) if isinstance(summary_field, str) and summary_field.strip().startswith("{") else None
                        if isinstance(parsed, dict):
                            vt_details = parsed
                            # produce a short textual summary (if available)
                            parsed_summary = parsed.get("summary") or parsed.get("result") or ""
                        else:
                            parsed_summary = summary_field
                    except Exception:
                        parsed_summary = summary_field
                    out.append({
                        "id": r[0],
                        "input": r[1] or "",
                        "type": r[2] or "",
                        "risk": r[3] or "",
                        "summary": parsed_summary or "",
                        "timestamp": r[5] or "",
                        "vt_details": vt_details
                    })
                conn.close()
                return out
        except Exception:
            pass

        # 3) Generic fallback: inspect tables and pick the first with rows
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cur.fetchall()]
            candidates = ["history", "scans", "scan", "records", "results"]
            for tbl in candidates:
                if tbl in tables:
                    try:
                        cur.execute(f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT ?", (limit,))
                        rows = cur.fetchall()
                        colnames = [d[0] for d in cur.description] if cur.description else []
                        if rows:
                            for r in rows:
                                rowd = {colnames[i]: r[i] for i in range(len(colnames))}
                                out.append({
                                    "id": rowd.get("id") or rowd.get("rowid") or "",
                                    "input": rowd.get("target") or rowd.get("input") or rowd.get("input_value") or "",
                                    "type": rowd.get("scan_type") or rowd.get("type") or "",
                                    "risk": rowd.get("status") or rowd.get("risk") or "",
                                    "summary": rowd.get("result_json") or rowd.get("summary") or "",
                                    "timestamp": rowd.get("created_at") or rowd.get("timestamp") or "",
                                    "vt_details": {}
                                })
                            conn.close()
                            return out
                    except Exception:
                        continue
        except Exception:
            pass

        conn.close()
        return out
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return []


# ---------------------------
# PDF Builder
# ---------------------------

def _make_metadata_table(scan_obj: dict):
    """
    Return a ReportLab Table for Metadata exactly in tabular format.
    """
    scan_id = scan_obj.get("id", "")
    input_val = scan_obj.get("input", "") or scan_obj.get("target", "")
    scan_type = scan_obj.get("type", "")
    risk = scan_obj.get("risk", "")
    summary = scan_obj.get("summary", "") or ""
    timestamp = scan_obj.get("timestamp", "") or ""

    rows = [
        ["Scan ID", str(scan_id)],
        ["Input", input_val],
        ["Type", scan_type],
        ["Risk Score", risk],
        ["Summary", summary if summary else "No summary available"],
        ["Timestamp (UTC)", str(timestamp)]
    ]

    tbl = Table(rows, colWidths=[180, 330])
    tbl.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.6, colors.black),
        ("BACKGROUND", (0,0), (0,-1), colors.whitesmoke),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ]))
    return tbl


def _make_section_table(title: str, rows: list):
    """
    Create a two-column table for a section (title handled outside).
    rows: list of [label, value]
    """
    tbl = Table(rows, colWidths=[180, 330])
    tbl.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BACKGROUND", (0,0), (0,-1), colors.whitesmoke)
    ]))
    return tbl


def build_report_pdf_bytes(scan_obj: dict) -> bytes:
    """
    Build and return PDF bytes for the given scan object.
    The structure matches the report_14 style: metadata table + 10 sections, all tables.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=36, bottomMargin=36, leftMargin=36, rightMargin=36)
    styles = getSampleStyleSheet()
    normal_style = styles["Normal"]
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=12, spaceAfter=6)

    story = []

    # Title
    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=20, spaceAfter=12)
    story.append(Paragraph("Metadata", title_style))
    story.append(Spacer(1, 6))

    # Metadata table
    story.append(_make_metadata_table(scan_obj))
    story.append(Spacer(1, 12))

    # Sections: use vt_details dict when available
    vt_details = {}
    if isinstance(scan_obj.get("vt_details"), dict):
        vt_details = scan_obj.get("vt_details")

    # Sections list - 10 sections, each has label/value rows
    sections = [
        ("1. URL Reputation & Categorization", [
            ["Reputation", vt_details.get("reputation", "No reputation / categorization details available.")],
            ["Category", vt_details.get("category", "No category information available.")],
            ["Harmless/Malicious Counts", vt_details.get("counts", "Not available.")]
        ]),
        ("2. Domain & Hosting Information", [
            ["Domain", vt_details.get("domain", "No domain/hosting metadata available.")],
            ["Registrar / WHOIS", vt_details.get("whois", "No public ownership (WHOIS) details were found.")],
            ["Hosting Country", vt_details.get("country", "Hosting country not specified.")],
            ["ASN / Network", vt_details.get("asn", "Network/ASN not reported.")]
        ]),
        ("3. DNS Records & Network Artifacts", [
            ["DNS Records", vt_details.get("dns", "No DNS records were reported for this link.")],
            ["IP Address candidates", vt_details.get("ips", "No IP candidates available.")]
        ]),
        ("4. Static Content Inspection", [
            ["HTML Title", vt_details.get("html_title", "No static content inspection details available.")],
            ["Detected Scripts / Links", vt_details.get("scripts", "No scripts/resources reported.")],
            ["Embedded Resources / Tags", vt_details.get("resources", "No notable embedded resources.")]
        ]),
        ("5. Dynamic Behavioral Analysis", [
            ["Redirect Chain", vt_details.get("redirects", "Not reported.")],
            ["Downloads Attempted", vt_details.get("downloads", "None.")],
            ["Execution Behavior", vt_details.get("execution", "No suspicious behavior detected.")]
        ]),
        ("6. Connections & Relationships", [
            ["Linked URLs / Files", vt_details.get("linked", "None found.")],
            ["Communicating Files", vt_details.get("files", "None found.")],
            ["Contacted Domains", vt_details.get("domains", "None found.")]
        ]),
        ("7. SSL/TLS Certificate Information", [
            ["Issuer", vt_details.get("cert_issuer", "Not available.")],
            ["Subject", vt_details.get("cert_subject", "Not available.")],
            ["Validity", vt_details.get("cert_validity", "Not available.")]
        ]),
        ("8. Antivirus / Engine Detections", [
            ["Last Analysis Stats", vt_details.get("av_stats", "No engine detection stats available.")],
            ["Malicious Engines", vt_details.get("av_malicious", "None reported.")]
        ]),
        ("9. Heuristic & Machine Learning Scoring", [
            ["ML/Heuristic Verdict", vt_details.get("ml_verdict", "No ML verdict provided.")],
            ["Heuristic Tags", vt_details.get("ml_tags", "None")]
        ]),
        ("10. Historical & Community Data", [
            ["Community Votes", vt_details.get("community", "No community votes.")],
            ["First Submission Date", vt_details.get("first_seen", "Unknown")],
            ["Last Analysis Date", vt_details.get("last_seen", "Unknown")]
        ])
    ]

    # Render sections as title + table
    for title, rows in sections:
        story.append(Paragraph(f"<b>{title}</b>", heading_style))
        story.append(_make_section_table(title, rows))
        story.append(Spacer(1, 12))

    # Footer note
    story.append(Spacer(1, 12))
    story.append(Paragraph("Generated by VirusLens — Cyber Threat Analyzer", normal_style))

    doc.build(story)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes


# ---------------------------
# Streamlit UI
# ---------------------------

st.title("Reports")
st.write("Generate printable PDF reports for completed scans. Select a scan below and click **Generate Report PDF**.")

db_path = get_db_path()
st.markdown("**DB:** " + f"`{str(db_path)}`")

# limit
limit = st.number_input("Limit (how many recent scans to list)", min_value=1, max_value=1000, value=200, step=1)


init_db(get_db_path())   # pass your preferred path if needed
scans = list_scans(limit=200)

# refresh / fetch scans
if st.button("Refresh scans"):
    safe_rerun()


scans = fetch_rows_from_db(db_path, limit=limit)

if not scans:
    st.info("No scans found in database (or DB not accessible). Perform scans first.")
    st.stop()

# present scans in selectbox
selected_scan = st.selectbox(
    "Select a scan",
    options=scans,
    format_func=lambda s: f"Scan {s.get('id','?')} — {s.get('input','(no input)')}"
)

scan_obj = selected_scan
scan_id = scan_obj.get("id", "")

st.markdown(f"**Selected scan:** `{scan_id}` — `{scan_obj.get('input','')}`")

# Generate PDF button
if st.button("Generate Report PDF"):
    try:
        pdf_bytes = build_report_pdf_bytes(scan_obj)
        filename = f"report_{scan_id}.pdf"
        st.success(f"PDF generated: {filename}")

        st.download_button(
            label="Download Report PDF",
            data=pdf_bytes,
            file_name=filename,
            mime="application/pdf"
        )
    except Exception as e:
        st.error(f"Failed to generate PDF: {e}")
        raise
