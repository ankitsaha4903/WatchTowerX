# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

import httpx
from .services import virustotal, urlscan, otx

def combine_verdicts(vt: str, us: str, pulses: int) -> str:
    v = [vt, us]
    if "malicious" in v:
        return "malicious"
    if pulses and pulses > 0:
        return "suspicious"
    if "suspicious" in v:
        return "suspicious"
    return "clean"

def summarize(url: str, vt_score: str, us_res: str, pulses: int, verdict: str) -> str:
    lines = [
        f"URL: {url}",
        f"VirusTotal: {vt_score}",
        f"urlscan.io: {us_res}",
        f"OTX pulses: {pulses}",
        f"Final verdict: {verdict}"
    ]
    return "\n".join(lines)

async def scan_url(url: str) -> dict:
    async with httpx.AsyncClient(follow_redirects=True) as session:
        vt = await virustotal.check_url(session, url)
        us = await urlscan.check_url(session, url)
        ot = await otx.check_url(session, url)

    vt_score = vt.get("score", "n/a")
    us_res = us.get("result", "n/a")
    pulses = int(str(ot.get("pulses", "0")).split(":")[-1]) if isinstance(ot.get("pulses"), str) else int(ot.get("pulses", 0))

    verdict = combine_verdicts(vt.get("verdict", "unknown"), us.get("verdict", "unknown"), pulses)
    summary = summarize(url, vt_score, us_res, pulses, verdict)

    return {
        "verdict": verdict,
        "summary": summary,
        "vt_score": vt_score,
        "urlscan_result": us_res,
        "otx_pulses": str(pulses),
    }
