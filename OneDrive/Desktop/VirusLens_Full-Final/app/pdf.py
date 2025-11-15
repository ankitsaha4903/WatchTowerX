"""
app/pdf.py

Generates a neat, white-background, black-font PDF report for a scan record.
Uses reportlab (pip install reportlab).

Public function:
    create_pdf_for_scan(scan_id, repo_getter)
        - scan_id: numeric id of scan record
        - repo_getter: a callable that returns the scan object when called with scan_id.
          (This keeps this module decoupled from your repo implementation. In main.py
           we'll pass app.repo.get_scan_by_id.)
Returns:
    path to generated PDF file (absolute or relative) on success.
Raises:
    ValueError / RuntimeError on failure.
"""

# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.rl_config import defaultPageSize

# page constants
PAGE_WIDTH, PAGE_HEIGHT = A4
LEFT_MARGIN = 18 * mm
RIGHT_MARGIN = 18 * mm
TOP_MARGIN = 18 * mm
BOTTOM_MARGIN = 18 * mm

# vertical space we consider reserved for header/footer when calculating remaining space
HEADER_HEIGHT = 18 * mm
FOOTER_HEIGHT = 12 * mm
LINE_HEIGHT = 10  # default line height in points for body text


def _ensure_reports_dir():
    out_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def _draw_header(c, title):
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(LEFT_MARGIN, PAGE_HEIGHT - TOP_MARGIN, title)
    # small divider line
    c.setLineWidth(0.5)
    c.line(LEFT_MARGIN, PAGE_HEIGHT - TOP_MARGIN - 6, PAGE_WIDTH - RIGHT_MARGIN, PAGE_HEIGHT - TOP_MARGIN - 6)


def _draw_footer(c, page_num):
    c.setFont("Helvetica", 8)
    footer_text = f"VirusLens — Generated {datetime.datetime.utcnow().isoformat(timespec='seconds')} UTC  •  page {page_num}"
    c.drawRightString(PAGE_WIDTH - RIGHT_MARGIN, BOTTOM_MARGIN - 6, footer_text)


def _available_height(c, y_cursor):
    # returns remaining height (points) from current y_cursor down to bottom margin + footer
    return y_cursor - (BOTTOM_MARGIN + FOOTER_HEIGHT)


def _start_new_page(c):
    c.showPage()
    # after showPage, need to re-setup color/font etc. Caller will draw header/footer


def _safe_get(d, key, default=""):
    if not d:
        return default
    return d.get(key, default)


def create_pdf_for_scan(scan_id, repo_getter):
    """
    Generate a PDF for a scan.

    scan_id: id of scan (int or str)
    repo_getter: callable(scan_id) -> object/dict representing scan details.

    Returns path to created PDF file.
    """

    # get the scan data via provided getter (keeps this module decoupled)
    scan = repo_getter(scan_id)
    if scan is None:
        raise ValueError(f"No scan found with id {scan_id}")

    out_dir = _ensure_reports_dir()
    filename = f"viruslens_report_{scan_id}.pdf"
    out_path = os.path.join(out_dir, filename)

    # open canvas
    c = canvas.Canvas(out_path, pagesize=A4)
    # white background: fill full page white (reportlab default is white, but ensure)
    c.setFillColorRGB(1, 1, 1)
    c.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, stroke=0, fill=1)
    c.setFillColorRGB(0, 0, 0)

    page_num = 1
    y = PAGE_HEIGHT - TOP_MARGIN - HEADER_HEIGHT  # starting y after header

    # add header & footer for first page
    _draw_header(c, f"VirusLens — Scan Report (id: {scan_id})")
    _draw_footer(c, page_num)

    # small top spacing
    y -= 16

    # helper to compute text height (approx, we keep simple)
    def text_block_height(lines, font_size=10):
        return len(lines) * (font_size + 2)

    # small helper to write a labeled block: title and list of lines
    def write_section(title, lines, font_name="Helvetica", font_size=10, spacing=6):
        nonlocal y, page_num
        # lines is list[str]
        if not lines:
            return

        block_h =  (font_size + 2) * (1 + len(lines)) + spacing  # title + each line
        avail = _available_height(c, y)
        if block_h > avail:
            # start a new page to keep the section intact
            _start_new_page(c)
            page_num += 1
            y = PAGE_HEIGHT - TOP_MARGIN - HEADER_HEIGHT
            _draw_header(c, f"VirusLens — Scan Report (id: {scan_id})")
            _draw_footer(c, page_num)
            y -= 16

        # draw title
        c.setFont(font_name + "-Bold" if font_name == "Helvetica" else font_name, font_size + 2)
        c.drawString(LEFT_MARGIN, y, title)
        y -= (font_size + 4)

        c.setFont(font_name, font_size)
        for ln in lines:
            if isinstance(ln, (list, tuple)):
                ln = " ".join(map(str, ln))
            # wrap long lines manually at a safe width
            max_width = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN
            # simple wrap: split by words
            words = str(ln).split()
            cur_line = ""
            for w in words:
                test = (cur_line + " " + w).strip()
                if c.stringWidth(test, font_name, font_size) > max_width:
                    c.drawString(LEFT_MARGIN, y, cur_line)
                    y -= (font_size + 2)
                    cur_line = w
                else:
                    cur_line = test
            if cur_line:
                c.drawString(LEFT_MARGIN, y, cur_line)
                y -= (font_size + 2)
        y -= spacing

    # Compose sections from scan object (safe getters)
    url = _safe_get(scan, "url", "n/a")
    verdict = _safe_get(scan, "verdict", "unknown")
    created_at = _safe_get(scan, "created_at", "")
    summary = _safe_get(scan, "summary", "")
    vt_score = _safe_get(scan, "vt_score", "n/a")
    urlscan_result = _safe_get(scan, "urlscan_result", "")
    otx = _safe_get(scan, "otx_pulses", "")

    # Section 1: Overview
    write_section(
        "1. Overview",
        [
            ("URL:", url),
            ("Verdict:", verdict),
            ("Created at (UTC):", str(created_at)),
            ("Summary:", summary or "No summary available"),
        ],
        font_size=11,
    )

    # Section 2: VirusTotal summary
    write_section(
        "2. VirusTotal",
        [
            ("VT score (malicious/total):", str(vt_score)),
            ("VT details:", str(_safe_get(scan, "vt_details", "Not available"))),
        ],
    )

    # Section 3: urlscan.io / other providers
    write_section(
        "3. urlscan / additional results",
        [
            ("urlscan result:", str(urlscan_result or "No urlscan data.")),
            ("OTX pulses:", str(otx or "No pulses available")),
        ],
    )

    # Section 4: Engine detections — put it as a single block (don't break inside)
    # Accept scan['av'] as list of tuples (name, text) or fallback based on vt details
    av_list = _safe_get(scan, "av", None)
    if not av_list:
        # Try derive from vt_details if present
        vt_details = _safe_get(scan, "vt_details", {})
        # vt_details may include 'last_analysis_stats' etc. Fallback textual summary:
        av_list = [("Last Analysis Stats", str(vt_details.get("last_analysis_stats", "n/a"))), ("Malicious Engines", "not available")]

    # Format av_list lines to readable strings
    av_lines = []
    for item in av_list:
        try:
            k, v = item
            av_lines.append(f"{k}: {v}")
        except Exception:
            av_lines.append(str(item))

    write_section("4. Antivirus / Engine Detections", av_lines)

    # Section 5: Notes / raw payload
    write_section("5. Raw / extra data", [("Raw URLscan payload:", str(urlscan_result or "n/a"))])

    # finish and save
    c.save()
    return out_path
