from __future__ import annotations
import re
import hashlib
import requests
from typing import Any, Dict, Optional
from app.utils.secrets import get_vt_api_key

# Regex fix (no inline (?i) in the middle)
HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")

def is_hash(s: str) -> bool:
    return bool(HASH_RE.match(s or ""))

def file_hash_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

class VTClient:
    def __init__(self, api_key: Optional[str] = None, base_url: str = "https://www.virustotal.com/api/v3"):
        self.api_key = api_key or get_vt_api_key()
        self.base_url = base_url
        self._session = requests.Session()
        self._session.headers.update({"x-apikey": self.api_key})

    def _check_key(self):
        if not self.api_key or len(self.api_key.strip()) < 20:
            raise RuntimeError("VirusTotal API key missing or invalid. Set VIRUSTOTAL_API_KEY in .env.")

    def _get(self, url: str) -> requests.Response:
        self.ratelimiter.wait()
        return requests.get(url, headers=self.headers, timeout=self.timeout)

    def _post(self, url: str, **kwargs) -> requests.Response:
        self.ratelimiter.wait()
        return requests.post(url, headers=self.headers, timeout=self.timeout, **kwargs)

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        self._check_key()
        r = self._get(f"{self.base}/files/{file_hash}")
        if r.status_code in (401, 404):
            return {"error": r.reason, "status_code": r.status_code}
        r.raise_for_status()
        return r.json()

    def analyze_url(self, url_value: str, poll: bool = True, max_wait: int = 35) -> Dict[str, Any]:
        self._check_key()
        submit = self._post(f"{self.base}/urls", data={"url": url_value})
        if submit.status_code == 401:
            return {"error": "Unauthorized (invalid API key)", "status_code": 401}
        submit.raise_for_status()
        data = submit.json()
        analysis_id = data.get("data", {}).get("id")
        if not poll or not analysis_id:
            return data

        start = time.time()
        while time.time() - start < max_wait:
            a = self._get(f"{self.base}/analyses/{analysis_id}")
            if a.status_code in (401, 429):
                if a.status_code == 429:
                    time.sleep(2)
                    continue
                return {"error": "Unauthorized (invalid API key)", "status_code": 401}
            a.raise_for_status()
            j = a.json()
            status = j.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return j
            time.sleep(1.0)
        return {"warning": "Timed out waiting for analysis", "data": data}

    def get_url_report(self, url_value: str) -> Dict[str, Any]:
        self._check_key()
        url_id = b64_url(url_value)
        r = self._get(f"{self.base}/urls/{url_id}")
        if r.status_code in (401, 404):
            return {"error": r.reason, "status_code": r.status_code}
        r.raise_for_status()
        return r.json()