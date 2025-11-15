# app/utils/paths.py
from __future__ import annotations
from pathlib import Path
from typing import Optional, Tuple

BASE_DIR: Path = Path(__file__).resolve().parents[1]
DATA_DIR: Path = BASE_DIR / "data"
REPORTS_DIR: Path = BASE_DIR / "reports"
CERTS_DIR: Path = BASE_DIR / "certs"

def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def report_file(scan_id: str | int) -> Path:
    safe = str(scan_id).replace("/", "_").replace("\\", "_")
    return REPORTS_DIR / f"report_{safe}.pdf"

def guess_local_cert() -> Optional[Tuple[Path, Path]]:
    if not CERTS_DIR.exists():
        return None
    candidates = list(CERTS_DIR.glob("*.pem"))
    keys = {p.stem.replace("-key", ""): p for p in CERTS_DIR.glob("*-key.pem")}
    for cert in candidates:
        key = CERTS_DIR / f"{cert.stem}-key.pem"
        if key.exists():
            return (cert, key)
    return None
