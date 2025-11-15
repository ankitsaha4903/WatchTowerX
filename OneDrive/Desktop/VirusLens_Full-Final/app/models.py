# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

# app/models.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from app.database import Base

"""
Scan model for VirusLens.
"""

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False, index=True)
    verdict = Column(String(64), nullable=True, default="unknown")
    summary = Column(Text, nullable=True)
    vt_score = Column(Integer, nullable=True)
    urlscan_result = Column(Text, nullable=True)
    otx_pulses = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    extra = Column(JSON, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "verdict": self.verdict,
            "summary": self.summary,
            "vt_score": self.vt_score,
            "urlscan_result": self.urlscan_result,
            "otx_pulses": self.otx_pulses,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "extra": self.extra,
        }
