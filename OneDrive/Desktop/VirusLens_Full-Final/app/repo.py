# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

# app/repo.py
"""
Repository helpers for VirusLens.

Provides:
 - get_db() dependency (delegates to app.database.get_db)
 - count_scans(db)
 - get_latest_scans(db, limit)
 - get_all_scans(db, limit)
 - get_scan_by_id(db, scan_id)
 - create_scan_from_url(db, url, **kwargs)
 - create_scan_from_file(db, filename, **kwargs)
 - process_csv_file(file_path, db)
 - scan_pasted_iocs(pasted_text, db)
"""

import csv
import io
from typing import Generator, List, Optional

from sqlalchemy.orm import Session

# delegate database dependency
from app.database import get_db as _get_db  # original dependency from database
from app.models import Scan

# Expose get_db as a generator function that yields from database.get_db()
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency wrapper. This yields a SQLAlchemy Session just like app.database.get_db.
    Keeps compatibility for callers importing get_db from app.repo.
    """
    yield from _get_db()


# ---- basic CRUD helpers ----

def count_scans(db: Session) -> int:
    """Return total number of scans."""
    # Use SQLAlchemy ORM API; works both for v1 and v2 style sessions
    return db.query(Scan).count()


def get_latest_scans(db: Session, limit: int = 10) -> List[Scan]:
    """Return latest scans ordered by created_at desc."""
    return (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )


def get_all_scans(db: Session, limit: int = 100) -> List[Scan]:
    """Return recent scans (default limit 100)."""
    return (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )


def get_scan_by_id(db: Session, scan_id: int) -> Optional[Scan]:
    """Fetch single scan by id or None."""
    return db.query(Scan).filter(Scan.id == scan_id).first()


def create_scan_from_url(
    db: Session,
    url: str,
    verdict: Optional[str] = None,
    summary: Optional[str] = None,
    vt_score: Optional[int] = None,
    urlscan_result: Optional[str] = None,
    otx_pulses: Optional[int] = None,
    extra: Optional[dict] = None,
) -> Scan:
    """Create a Scan record for a URL and return the persisted object."""
    scan = Scan(
        url=url,
        verdict=verdict or "unknown",
        summary=summary,
        vt_score=vt_score,
        urlscan_result=urlscan_result,
        otx_pulses=otx_pulses,
        extra=extra,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def create_scan_from_file(
    db: Session,
    filename: str,
    verdict: Optional[str] = None,
    summary: Optional[str] = None,
    vt_score: Optional[int] = None,
    urlscan_result: Optional[str] = None,
    otx_pulses: Optional[int] = None,
    extra: Optional[dict] = None,
) -> Scan:
    """Create a Scan record for a file (store filename in url column)."""
    # We reuse same Scan model but save the filename in 'url' for now.
    return create_scan_from_url(
        db=db,
        url=filename,
        verdict=verdict,
        summary=summary,
        vt_score=vt_score,
        urlscan_result=urlscan_result,
        otx_pulses=otx_pulses,
        extra=extra,
    )


# ---- CSV and pasted IOC processing ----

def process_csv_file(file_path: str, db: Session, limit: Optional[int] = None) -> List[Scan]:
    """
    Read a CSV of IOC lines. Expected CSV structure:
      - either single column of input (URL/hash)
      - or columns (input,type) where type is optional

    This will create Scan entries for each parsed record.
    Returns the list of created Scan objects.
    """
    created = []
    with open(file_path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for i, row in enumerate(reader):
            if limit is not None and i >= limit:
                break
            # skip empty rows
            if not row:
                continue
            # prefer first column as input
            input_val = str(row[0]).strip()
            if not input_val:
                continue
            # optional type in second column (not used here but preserved)
            # type_val = row[1].strip() if len(row) > 1 else None
            scan = create_scan_from_url(db=db, url=input_val, summary="Imported from CSV")
            created.append(scan)
    return created


def scan_pasted_iocs(pasted_text: str, db: Session, limit: Optional[int] = None) -> List[Scan]:
    """
    Accepts pasted text (one IOC per line), creates scans for each non-empty line.
    Returns list of created Scan objects.
    """
    created = []
    stream = io.StringIO(pasted_text or "")
    for i, raw in enumerate(stream):
        if limit is not None and i >= limit:
            break
        line = raw.strip()
        if not line:
            continue
        scan = create_scan_from_url(db=db, url=line, summary="Imported from pasted IOCs")
        created.append(scan)
    return created


# Expose names for "from app.repo import get_db, count_scans, ..."
__all__ = [
    "get_db",
    "count_scans",
    "get_latest_scans",
    "get_all_scans",
    "get_scan_by_id",
    "create_scan_from_url",
    "create_scan_from_file",
    "process_csv_file",
    "scan_pasted_iocs",
]
