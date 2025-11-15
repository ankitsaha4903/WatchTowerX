import httpx
from ..config import settings

BASE = "https://otx.alienvault.com/api/v1/indicators/url/{url}/general"

async def check_url(session: httpx.AsyncClient, url: str) -> dict:
    if settings.MOCK_MODE or not settings.OTX_API_KEY:
        return {"pulses": "mock:0"}
    headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
    r = await session.get(BASE.format(url=url), headers=headers, timeout=30)
    r.raise_for_status()
    d = r.json()
    pulses = len(d.get("pulse_info", {}).get("pulses", []))
    return {"pulses": str(pulses)}
