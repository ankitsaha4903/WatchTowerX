import httpx
from ..config import settings

BASE = "https://www.virustotal.com/api/v3/urls"

async def check_url(session: httpx.AsyncClient, url: str) -> dict:
    if settings.MOCK_MODE or not settings.VT_API_KEY:
        # deterministic mock
        verdict = "malicious" if any(x in url for x in ["mal", "phish", "bad"]) else "clean"
        return {"verdict": verdict, "score": "mock:1/90" if verdict=="malicious" else "mock:0/90"}

    # VT requires url-id = base64(url) with special encoding; use the "analyze" and then "get" pattern
    headers = {"x-apikey": settings.VT_API_KEY}
    # submit
    r = await session.post(BASE, headers=headers, data={"url": url}, timeout=30)
    r.raise_for_status()
    data = r.json()
    url_id = data.get("data", {}).get("id")
    # fetch analysis
    r2 = await session.get(f"{BASE}/{url_id}", headers=headers, timeout=30)
    r2.raise_for_status()
    d = r2.json()
    stats = d.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    verdict = "malicious" if mal > 0 else "clean"
    return {"verdict": verdict, "score": f"{mal}/{total}"}
