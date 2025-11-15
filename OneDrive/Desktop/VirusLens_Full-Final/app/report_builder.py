"""
app/report_builder.py
----------------------------------------------------
VirusLens — Layman-Friendly Report Generator
- Same 10 sections (Aspects unchanged)
- Details rewritten in simple, non-technical language
- White background; no hidden glyphs (no black dots)
- LongTable + chunking prevents page-overflow LayoutError
- No Raw JSON appendix
----------------------------------------------------
"""

# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.platypus.tables import LongTable, TableStyle
from xml.sax.saxutils import escape as xml_escape


# =============================== Styles ==================================== #

_styles = getSampleStyleSheet()

H1 = ParagraphStyle(
    name="H1", parent=_styles["Heading1"], fontName="Helvetica-Bold",
    fontSize=18, leading=22, alignment=TA_LEFT, textColor=colors.black
)
H2 = ParagraphStyle(
    name="H2", parent=_styles["Heading2"], fontName="Helvetica-Bold",
    fontSize=13, leading=16, textColor=colors.black
)
BODY = ParagraphStyle(
    name="Body", parent=_styles["BodyText"], fontName="Helvetica",
    fontSize=10, leading=13, textColor=colors.black, wordWrap="CJK"
)
CELL = ParagraphStyle(
    name="Cell", parent=BODY, fontSize=9, leading=12, wordWrap="CJK"
)
CELL_HEADER = ParagraphStyle(
    name="CellHeader", parent=BODY, fontName="Helvetica-Bold", fontSize=9, wordWrap="CJK"
)


# ============================ Small helpers ================================= #

def _p(text: str, style: ParagraphStyle = CELL) -> Paragraph:
    """HTML-safe Paragraph that auto-wraps; no zero-width characters used."""
    safe = xml_escape(text if text is not None else "—").replace("\n", "<br/>")
    if not safe:
        safe = "—"
    return Paragraph(safe, style)

def _chunk_lines(txt: str, hard_chunk: int = 300) -> List[str]:
    """
    Break long text into multiple chunks so a single table row never grows
    taller than the page. Split by lines, then hard-chunk each long line.
    """
    parts: List[str] = []
    for line in (txt or "").splitlines() or [""]:
        if len(line) <= hard_chunk:
            parts.append(line)
        else:
            for i in range(0, len(line), hard_chunk):
                parts.append(line[i:i + hard_chunk])
    return parts or [""]

def _expand_row(label: str, value_text: str) -> List[List[Paragraph]]:
    """
    Turn (label, value_text) into multiple rows when needed:
      - Row 1: label + first chunk
      - Rows 2..n: ''  + remaining chunks
    """
    rows: List[List[Paragraph]] = []
    for i, chunk in enumerate(_chunk_lines(value_text, 300)):
        rows.append([_p(label if i == 0 else "", CELL_HEADER if i == 0 else CELL), _p(chunk)])
    return rows

def _make_long_table(rows: List[Tuple[str, str]], col_widths=(6 * cm, 10 * cm)) -> LongTable:
    """Build a LongTable with header and wrapped cells; rows can split across pages."""
    header = [_p("Aspect", CELL_HEADER), _p("Details", CELL_HEADER)]
    body: List[List[Paragraph]] = []
    for label, text in rows:
        body.extend(_expand_row(label, text))

    t = LongTable([header] + body, colWidths=list(col_widths), repeatRows=1, splitByRow=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),

        ("GRID", (0, 0), (-1, -1), 0.3, colors.gray),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.gray),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),

        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t

def _get(raw: Dict[str, Any], path: List[str]) -> Any:
    cur = raw
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur

def _fmt_epoch(ts: Any) -> Optional[str]:
    try:
        # VirusTotal returns unix epoch seconds
        return datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
    except Exception:
        return None

def _list_to_english(items: List[str], max_items: int = 6) -> str:
    items = [str(x) for x in items if x]
    if not items:
        return "None"
    if len(items) > max_items:
        head = ", ".join(items[:max_items])
        return f"{head}, and {len(items) - max_items} more"
    return ", ".join(items)


# ======================== Layman-language mappers ========================== #

def layman_reputation(rep: Any) -> str:
    try:
        rep = int(rep or 0)
    except Exception:
        rep = 0
    if rep > 5:
        level = "High risk"
    elif rep > 1:
        level = "Suspicious"
    else:
        level = "Low risk"
    return f"Overall reputation score is {rep} → {level}."

def layman_categories(cats: Any) -> str:
    """
    VT sometimes returns a dict of vendor→category. We’ll show unique categories.
    """
    if isinstance(cats, dict):
        unique = sorted({str(v) for v in cats.values() if v})
        if unique:
            return "This link is mostly about: " + _list_to_english(unique)
    if isinstance(cats, list):
        return "Categories: " + _list_to_english([str(x) for x in cats])
    return "No clear category was reported."

def layman_stats(stats: Any) -> str:
    if not isinstance(stats, dict):
        return "No engine summary was provided."
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    suspicious = stats.get("suspicious", 0)
    malicious = stats.get("malicious", 0)
    timeout = stats.get("timeout", 0)
    total = sum(int(stats.get(k, 0)) for k in ["harmless", "undetected", "suspicious", "malicious", "timeout"])
    return (
        f"Checked by {total} security sources: "
        f"{harmless} said clean, {undetected} had no data, "
        f"{suspicious} were unsure, {malicious} flagged as harmful, "
        f"{timeout} did not respond."
    )

def layman_domain_id(raw: Dict[str, Any]) -> str:
    return str(_get(raw, ["data", "id"]) or _get(raw, ["data", "links", "self"]) or "Not available")

def layman_whois(raw: Dict[str, Any]) -> str:
    whois = _get(raw, ["data", "attributes", "whois"])
    if whois:
        return "Basic ownership information is available."
    return "No public ownership (WHOIS) details were found."

def layman_country(raw: Dict[str, Any]) -> str:
    c = _get(raw, ["data", "attributes", "country"])
    return str(c) if c else "Hosting country not specified."

def layman_asn(raw: Dict[str, Any]) -> str:
    a = _get(raw, ["data", "attributes", "asn"])
    return f"Network/ASN: {a}" if a else "Network/ASN not reported."

def layman_dns(raw: Dict[str, Any]) -> str:
    r = _get(raw, ["data", "attributes", "last_dns_records"])
    if r:
        try:
            return f"Some DNS records were found (technical entries that map names to servers)."
        except Exception:
            pass
    return "No DNS records were reported for this link."

def layman_ip_candidates(stats: Any) -> str:
    """
    Instead of raw engines list, give a human summary using last_analysis_stats.
    """
    if not isinstance(stats, dict):
        return "Security sources checked this link; none reported it as malicious."
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    malicious = stats.get("malicious", 0)
    if malicious:
        return f"Some sources flagged it ({malicious} harmful reports). Treat with caution."
    return f"Reviewed by many sources: {harmless} said clean, {undetected} had no data."

def layman_html_title(raw: Dict[str, Any]) -> str:
    t = _get(raw, ["data", "attributes", "title"])
    return f"Page title: {t}" if t else "No page title available."

def layman_scripts(raw: Dict[str, Any]) -> str:
    links = _get(raw, ["data", "attributes", "outgoing_links"]) or []
    if isinstance(links, list) and links:
        examples = [str(x) for x in links[:5]]
        return f"This page loads external scripts/resources (e.g., { _list_to_english(examples, max_items=5) })."
    return "No external scripts or links were listed."

def layman_tags(raw: Dict[str, Any]) -> str:
    tags = _get(raw, ["data", "attributes", "tags"]) or []
    if isinstance(tags, list) and tags:
        return "Notable labels on this page: " + _list_to_english([str(x) for x in tags], max_items=8)
    return "No notable labels were attached."

def layman_redirects(raw: Dict[str, Any]) -> str:
    chain = _get(raw, ["data", "attributes", "redirection_chain"]) or []
    if isinstance(chain, list) and chain:
        return f"This link redirects {len(chain)} time(s) before loading."
    return "No redirects were observed."

def layman_downloads(raw: Dict[str, Any]) -> str:
    d = _get(raw, ["data", "attributes", "downloaded_files"])
    return "No automatic downloads were seen." if not d else "The page attempted to download file(s)."

def layman_behavior(raw: Dict[str, Any]) -> str:
    b = _get(raw, ["data", "attributes", "behaviour_summary"])
    return "No suspicious behavior was seen while loading the page." if not b else "Some runtime behavior was captured."

def layman_relationships(raw: Dict[str, Any], key: List[str], label: str) -> str:
    rel = _get(raw, key)
    if rel:
        return f"Related {label} were referenced."
    return f"No related {label} were found."

def layman_cert_field(raw: Dict[str, Any], field: str, label: str) -> str:
    v = _get(raw, ["data", "attributes", "last_https_certificate", field])
    if v:
        return f"{label}: information present."
    return f"{label}: not available."

def layman_votes(raw: Dict[str, Any]) -> str:
    v = _get(raw, ["data", "attributes", "total_votes"]) or {}
    harmless = v.get("harmless", 0) if isinstance(v, dict) else 0
    malicious = v.get("malicious", 0) if isinstance(v, dict) else 0
    if harmless == 0 and malicious == 0:
        return "No community votes yet."
    return f"Community votes — Safe: {harmless}, Unsafe: {malicious}."

def layman_date_field(raw: Dict[str, Any], path: List[str], label: str) -> str:
    ts = _get(raw, path)
    iso = _fmt_epoch(ts)
    return f"{label}: {iso}" if iso else f"{label}: not available."


# =============================== Main builder =============================== #

def make_pdf_report(path: str, title: str, metadata: Dict[str, Any], raw_json: Dict[str, Any]):
    """
    Generate the VirusLens PDF report with 10 sections.
    - Layman-language details
    - White background; wrapped cells
    - LongTable + chunking (no LayoutError)
    - No Raw JSON appendix
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=1.6 * cm,
        leftMargin=1.6 * cm,
        topMargin=1.6 * cm,
        bottomMargin=1.6 * cm,
        allowSplitting=1,
    )

    story: List[Any] = []

    # Header
    story.append(Paragraph(title, H1))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", BODY))
    story.append(Spacer(1, 0.5 * cm))

    # ---- Metadata (converted to plain sentences where helpful) ---- #
    meta_pairs: List[Tuple[str, str]] = [
        ("Scan ID", str(metadata.get("Scan ID", "—"))),
        ("Input", str(metadata.get("Input", "—"))),
        ("Type", str(metadata.get("Type", "—"))),
        ("Risk Score", str(metadata.get("Risk Score", "—"))),
        ("Summary", str(metadata.get("Summary", "—"))),
        ("Timestamp (UTC)", str(metadata.get("Timestamp (UTC)", "—"))),
    ]
    story.append(Paragraph("Metadata", H2))
    story.append(_make_long_table(meta_pairs))
    story.append(Spacer(1, 0.5 * cm))

    # 1) URL Reputation & Categorization
    story.append(Paragraph("1. URL Reputation & Categorization", H2))
    sec1: List[Tuple[str, str]] = [
        ("Reputation", layman_reputation(_get(raw_json, ["data", "attributes", "reputation"]))),
        ("Category", layman_categories(_get(raw_json, ["data", "attributes", "categories"]))),
        ("Harmless/Malicious Counts", layman_stats(_get(raw_json, ["data", "attributes", "last_analysis_stats"]))),
    ]
    story.append(_make_long_table(sec1))
    story.append(Spacer(1, 0.4 * cm))

    # 2) Domain & Hosting Information
    story.append(Paragraph("2. Domain & Hosting Information", H2))
    sec2: List[Tuple[str, str]] = [
        ("Domain (ID/URL)", layman_domain_id(raw_json)),
        ("Registrar / WHOIS", layman_whois(raw_json)),
        ("Hosting Country", layman_country(raw_json)),
        ("ASN / Network", layman_asn(raw_json)),
    ]
    story.append(_make_long_table(sec2))
    story.append(Spacer(1, 0.4 * cm))

    # 3) DNS Records & Network Artifacts
    story.append(Paragraph("3. DNS Records & Network Artifacts", H2))
    sec3: List[Tuple[str, str]] = [
        ("DNS Records", layman_dns(raw_json)),
        ("IP Address candidates", layman_ip_candidates(_get(raw_json, ["data", "attributes", "last_analysis_stats"]))),
    ]
    story.append(_make_long_table(sec3))
    story.append(Spacer(1, 0.4 * cm))

    # 4) Static Content Inspection
    story.append(Paragraph("4. Static Content Inspection", H2))
    sec4: List[Tuple[str, str]] = [
        ("HTML Title", layman_html_title(raw_json)),
        ("Detected Scripts / Links", layman_scripts(raw_json)),
        ("Embedded Resources / Tags", layman_tags(raw_json)),
    ]
    story.append(_make_long_table(sec4))
    story.append(Spacer(1, 0.4 * cm))

    # 5) Dynamic Behavioral Analysis
    story.append(Paragraph("5. Dynamic Behavioral Analysis", H2))
    sec5: List[Tuple[str, str]] = [
        ("Redirect Chain", layman_redirects(raw_json)),
        ("Downloads Attempted", layman_downloads(raw_json)),
        ("Execution Behavior Summary", layman_behavior(raw_json)),
    ]
    story.append(_make_long_table(sec5))
    story.append(Spacer(1, 0.4 * cm))

    # 6) Connections & Relationships
    story.append(Paragraph("6. Connections & Relationships", H2))
    sec6: List[Tuple[str, str]] = [
        ("Linked URLs / Files", layman_relationships(raw_json, ["data", "relationships", "downloaded_files"], "items")),
        ("Communicating Files", layman_relationships(raw_json, ["data", "relationships", "communicating_files"], "files")),
        ("Contacted Domains", layman_relationships(raw_json, ["data", "relationships", "contacted_domains"], "domains")),
    ]
    story.append(_make_long_table(sec6))
    story.append(Spacer(1, 0.4 * cm))

    # 7) SSL/TLS Certificate Information
    story.append(Paragraph("7. SSL/TLS Certificate Information", H2))
    sec7: List[Tuple[str, str]] = [
        ("Issuer", layman_cert_field(raw_json, "issuer", "Certificate issuer")),
        ("Subject", layman_cert_field(raw_json, "subject", "Certificate subject")),
        ("Validity", layman_cert_field(raw_json, "validity", "Certificate validity period")),
    ]
    story.append(_make_long_table(sec7))
    story.append(Spacer(1, 0.4 * cm))

    # 8) Antivirus / Engine Detections
    story.append(Paragraph("8. Antivirus / Engine Detections", H2))
    last_stats = _get(raw_json, ["data", "attributes", "last_analysis_stats"]) or {}
    last_results = _get(raw_json, ["data", "attributes", "last_analysis_results"]) or {}
    malicious_engs = [k for k, v in (last_results.items() if isinstance(last_results, dict) else []) if isinstance(v, dict) and v.get("category") == "malicious"]
    sec8: List[Tuple[str, str]] = [
        ("Last Analysis Stats", layman_stats(last_stats)),
        ("Malicious Engines", "None of the engines flagged this link as harmful." if not malicious_engs else f"Flagged by: {_list_to_english(malicious_engs, max_items=10)}"),
    ]
    story.append(_make_long_table(sec8))
    story.append(Spacer(1, 0.4 * cm))

    # 9) Heuristic & Machine Learning Scoring
    story.append(Paragraph("9. Heuristic & Machine Learning Scoring", H2))
    verdict = _get(raw_json, ["data", "attributes", "verdict"])
    tags = _get(raw_json, ["data", "attributes", "tags"]) or []
    plain_verdict = "No automated (ML/heuristic) verdict was provided." if not verdict else f"Automated verdict: {verdict}"
    plain_tags = "No heuristic tags were attached." if not tags else "Heuristic tags: " + _list_to_english([str(x) for x in tags], max_items=12)
    sec9: List[Tuple[str, str]] = [
        ("ML/Heuristic Verdict", plain_verdict),
        ("Heuristic Tags", plain_tags),
    ]
    story.append(_make_long_table(sec9))
    story.append(Spacer(1, 0.4 * cm))

    # 10) Historical & Community Data
    story.append(Paragraph("10. Historical & Community Data", H2))
    sec10: List[Tuple[str, str]] = [
        ("Community Votes", layman_votes(raw_json)),
        ("First Submission Date", layman_date_field(raw_json, ["data", "attributes", "first_submission_date"], "First seen")),
        ("Last Analysis Date", layman_date_field(raw_json, ["data", "attributes", "last_analysis_date"], "Last checked")),
    ]
    story.append(_make_long_table(sec10))
    story.append(Spacer(1, 0.4 * cm))

    # Build PDF
    doc.build(story)
