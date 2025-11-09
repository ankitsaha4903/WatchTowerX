import os
import time
import requests
from dotenv import load_dotenv
from typing import Tuple, Dict, Any

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
if not VT_API_KEY:
    raise RuntimeError("VT_API_KEY missing in .env")

BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

def analyze_url(url: str, poll: bool = True, timeout_s: int = 25) -> Dict[str, Any]:
    """Submit a URL for analysis and optionally poll for completion."""
    submit = requests.post(f"{BASE}/urls", headers=HEADERS, data={"url": url})
    submit.raise_for_status()
    analysis_id = submit.json()["data"]["id"]

    if not poll:
        return {"analysis_id": analysis_id}

    start = time.time()
    while True:
        resp = requests.get(f"{BASE}/analyses/{analysis_id}", headers=HEADERS)
        resp.raise_for_status()
        data = resp.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            return data
        if time.time() - start > timeout_s:
            return data  # partial/timeout
        time.sleep(2)

def get_url_report(url_id: str) -> Dict[str, Any]:
    r = requests.get(f"{BASE}/urls/{url_id}", headers=HEADERS)
    r.raise_for_status()
    return r.json()

def get_file_report_by_hash(file_hash: str) -> Tuple[Dict[str, Any] | None, int]:
    resp = requests.get(f"{BASE}/files/{file_hash}", headers=HEADERS)
    if resp.status_code == 200:
        return resp.json(), 200
    return None, resp.status_code

def vt_web_link(kind: str, id_or_hash: str) -> str:
    if kind == "url":
        return f"https://www.virustotal.com/gui/url/{id_or_hash}"
    return f"https://www.virustotal.com/gui/file/{id_or_hash}"
