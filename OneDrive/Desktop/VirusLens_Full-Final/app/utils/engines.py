# app/utils/engines.py
from __future__ import annotations
import os
import time
import json
import hashlib
import requests
from typing import Any, Dict, List, Optional, Tuple

from app.utils.secrets import get_vt_api_key

# ---------- Helpers ----------

def detect_ioc_type(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return "unknown"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    # crude hash detection (md5/sha1/sha256)
    hv = v.lower()
    if len(hv) in (32, 40, 64) and all(c in "0123456789abcdef" for c in hv):
        return "hash"
    return "unknown"

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------- VirusTotal ----------

def vt_headers() -> Dict[str, str]:
    return {"x-apikey": get_vt_api_key()}

def vt_url_report(url: str) -> Dict[str, Any]:
    # VT needs an id = url_id (base64-url of the url). The simple “scan + fetch” route works too.
    s = requests.Session()
    s.headers.update(vt_headers())

    # submit (harmless if already known)
    submit = s.post("https://www.virustotal.com/api/v3/urls", data={"url": url})
    submit.raise_for_status()
    url_id = submit.json().get("data", {}).get("id")

    # fetch analysis
    r = s.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}")
    # some analyses need a moment
    tries = 0
    while r.status_code == 200 and r.json().get("data", {}).get("attributes", {}).get("status") != "completed" and tries < 12:
        time.sleep(1)
        r = s.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}")

    r.raise_for_status()
    data = r.json()
    stats = data.get("data", {}).get("attributes", {}).get("stats", {}) or {}
    categories = {}
    # categories require the url object
    if url_id:
        ur = s.get(f"https://www.virustotal.com/api/v3/urls/{url_id}")
        if ur.ok:
            categories = ur.json().get("data", {}).get("attributes", {}).get("categories", {}) or {}

    return {
        "engine": "VirusTotal",
        "raw": data,
        "summary": {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "timeout": int(stats.get("timeout", 0)),
            "categories": categories,
        },
    }

def vt_hash_report(hash_value: str) -> Dict[str, Any]:
    s = requests.Session()
    s.headers.update(vt_headers())
    r = s.get(f"https://www.virustotal.com/api/v3/files/{hash_value}")
    if r.status_code == 404:
        return {"engine": "VirusTotal", "raw": {}, "summary": {"error": "Hash not found"}}
    r.raise_for_status()
    data = r.json()
    attrs = data.get("data", {}).get("attributes", {}) or {}
    stats = (attrs.get("last_analysis_stats") or {})
    return {
        "engine": "VirusTotal",
        "raw": data,
        "summary": {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "timeout": int(stats.get("timeout", 0)),
            "size": attrs.get("size"),
            "type_description": attrs.get("type_description"),
        },
    }

# ---------- urlscan.io (optional) ----------

def urlscan_enabled() -> bool:
    return bool(os.getenv("URLSCAN_API_KEY"))

def urlscan_report(url: str) -> Dict[str, Any]:
    api = os.getenv("URLSCAN_API_KEY")
    if not api:
        return {"engine": "urlscan.io", "summary": {"skipped": "no API key"}}
    s = requests.Session()
    s.headers.update({"API-Key": api, "Content-Type": "application/json"})
    sub = s.post("https://urlscan.io/api/v1/scan/", data=json.dumps({"url": url, "public": "off"}))
    sub.raise_for_status()
    result = sub.json()
    # poll result
    uuid = result.get("uuid")
    time.sleep(2)
    rep = s.get(f"https://urlscan.io/api/v1/result/{uuid}/")
    tries = 0
    while rep.status_code == 404 and tries < 12:
        time.sleep(2)
        rep = s.get(f"https://urlscan.io/api/v1/result/{uuid}/")
        tries += 1
    if rep.status_code != 200:
        return {"engine": "urlscan.io", "summary": {"error": f"status {rep.status_code}"}}
    data = rep.json()
    verdicts = (data.get("verdicts") or {})
    overall = (verdicts.get("overall") or {})
    cat = data.get("meta", {}).get("processors", {}).get("categorization", {})
    cats = {}
    if isinstance(cat, dict):
        for prov, items in cat.items():
            # each provider map -> take first category if present
            if isinstance(items, list) and items:
                cats[prov] = items[0].get("category")
    return {
        "engine": "urlscan.io",
        "raw": data,
        "summary": {
            "score": overall.get("score"),
            "malicious": 1 if overall.get("malicious") else 0,
            "categories": cats,
        },
    }

# ---------- AlienVault OTX (optional) ----------

def otx_enabled() -> bool:
    return bool(os.getenv("OTX_API_KEY"))

def otx_report(ioc: str, ioc_type: str) -> Dict[str, Any]:
    api = os.getenv("OTX_API_KEY")
    if not api:
        return {"engine": "AlienVault OTX", "summary": {"skipped": "no API key"}}
    s = requests.Session()
    s.headers.update({"X-OTX-API-KEY": api})
    if ioc_type == "url":
        endpoint = "indicators/url"
    elif ioc_type == "hash":
        endpoint = "indicators/file"
    else:
        return {"engine": "AlienVault OTX", "summary": {"skipped": "unsupported type"}}
    r = s.get(f"https://otx.alienvault.com/api/v1/{endpoint}/{ioc}/general")
    if r.status_code == 404:
        return {"engine": "AlienVault OTX", "summary": {"not_found": True}}
    if not r.ok:
        return {"engine": "AlienVault OTX", "summary": {"error": f"status {r.status_code}"}}
    data = r.json()
    pulses = data.get("pulse_info", {}).get("count", 0)
    return {
        "engine": "AlienVault OTX",
        "raw": data,
        "summary": {
            "pulses": pulses,
            "malicious": 1 if pulses and pulses > 0 else 0,
        },
    }

# ---------- Aggregation ----------

def aggregate_scan(ioc: str, ioc_type: Optional[str] = None) -> Dict[str, Any]:
    t = ioc_type or detect_ioc_type(ioc)
    engines: List[Dict[str, Any]] = []

    # VirusTotal (required key)
    try:
        if t == "url":
            engines.append(vt_url_report(ioc))
        elif t == "hash":
            engines.append(vt_hash_report(ioc))
    except Exception as e:
        engines.append({"engine": "VirusTotal", "summary": {"error": str(e)}})

    # urlscan.io (optional, URL only)
    if t == "url" and urlscan_enabled():
        try:
            engines.append(urlscan_report(ioc))
        except Exception as e:
            engines.append({"engine": "urlscan.io", "summary": {"error": str(e)}})

    # OTX (optional)
    if otx_enabled():
        try:
            engines.append(otx_report(ioc, t))
        except Exception as e:
            engines.append({"engine": "AlienVault OTX", "summary": {"error": str(e)}})

    # Simple combined risk score
    total_mal = 0
    total_susp = 0
    for e in engines:
        s = e.get("summary", {})
        total_mal += int(s.get("malicious", 0) or 0)
        total_susp += int(s.get("suspicious", 0) or 0)

    overall = "Low"
    if total_mal >= 1:
        overall = "High"
    elif total_susp >= 1:
        overall = "Medium"

    return {
        "input": ioc,
        "type": t,
        "overall_risk": overall,
        "engines": engines,
    }
