import httpx
from ..config import settings

SUBMIT = "https://urlscan.io/api/v1/scan/"
RESULT = "https://urlscan.io/api/v1/result/{uuid}"

async def check_url(session: httpx.AsyncClient, url: str) -> dict:
    if settings.MOCK_MODE or not settings.URLSCAN_API_KEY:
        # mock: flag .exe/.zip as suspicious
        verdict = "suspicious" if any(url.endswith(x) for x in [".exe",".zip"]) else "clean"
        return {"verdict": verdict, "result": "mock-ok"}

    headers = {"API-Key": settings.URLSCAN_API_KEY, "Content-Type": "application/json"}
    r = await session.post(SUBMIT, headers=headers, json={"url": url, "visibility": "private"}, timeout=30)
    r.raise_for_status()
    uuid = r.json().get("uuid")

    # poll once (simple)
    r2 = await session.get(RESULT.format(uuid=uuid), headers=headers, timeout=30)
    if r2.status_code == 404:
        # give it a moment; in real app add polling/backoff
        return {"verdict": "unknown", "result": "pending"}
    r2.raise_for_status()
    d = r2.json()
    # naive: if "malicious" categories present
    verdict = "malicious" if d.get("verdicts", {}).get("overall", {}).get("score", 0) > 50 else "clean"
    return {"verdict": verdict, "result": uuid}
