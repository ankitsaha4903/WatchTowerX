from typing import Dict, Any, Tuple

def compute_risk(stats: Dict[str, Any]) -> int:
    # Simple, explainable heuristic
    m = int(stats.get("malicious", 0))
    s = int(stats.get("suspicious", 0))
    h = int(stats.get("harmless", 0))
    score = m*25 + s*10 - min(h, 5)*2
    return max(0, min(score, 100))

def summarize_stats(vt_json: Dict[str, Any]) -> Dict[str, Any]:
    if not vt_json:
        return {}
    attrs = None
    if isinstance(vt_json.get("data"), dict):
        attrs = vt_json["data"].get("attributes")
    if not attrs and "attributes" in vt_json:
        attrs = vt_json["attributes"]
    if not attrs:
        return {}
    stats = attrs.get("last_analysis_stats", {})
    reputation = attrs.get("reputation")
    harmless = stats.get("harmless", 0)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    return {
        "harmless": harmless,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "timeout": timeout,
        "reputation": reputation,
    }

def verdict_text(score: int) -> Tuple[str, str]:
    if score >= 70:
        return ("High Risk", "🔥")
    if score >= 40:
        return ("Moderate Risk", "⚠️")
    return ("Low Risk", "🟢")