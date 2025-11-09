import base64
from typing import Dict, Any

STATUS_BADGES = {
    "harmless": "✅ Harmless",
    "malicious": "🛑 Malicious",
    "suspicious": "⚠️ Suspicious",
    "undetected": "ℹ️ Undetected",
    "timeout": "⏳ Timeout",
}

def url_id_from_plain(url: str) -> str:
    """
    VirusTotal needs urlsafe base64 without padding for /urls/{id}
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.strip("=")

def parse_stats(stats: Dict[str, Any]) -> Dict[str, int]:
    """Normalize last_analysis_stats to known keys."""
    defaults = {"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0, "timeout": 0}
    return {k: int(stats.get(k, 0)) for k in defaults}

def verdict_from_stats(stats: Dict[str, int]) -> str:
    if stats.get("malicious", 0) > 0:
        return "malicious"
    if stats.get("suspicious", 0) > 0:
        return "suspicious"
    if stats.get("harmless", 0) > 0 and stats.get("malicious", 0) == 0 and stats.get("suspicious", 0) == 0:
        return "harmless"
    return "undetected"
def vt_web_link(kind: str, id_value: str) -> str:
    kind = (kind or "").lower()
    if kind == "url":
        return f"https://www.virustotal.com/gui/url/{id_value}"
    if kind in ("file", "hash"):
        return f"https://www.virustotal.com/gui/file/{id_value}"
    return "https://www.virustotal.com/"


