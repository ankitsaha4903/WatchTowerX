# storage.py
#
# Safe, Streamlit-friendly storage layer.
# - On Windows (local): tries to scan installed apps via registry (scanner_windows.py).
# - On all other OS (including Streamlit Cloud Linux): uses sample data.
# - Never raises FileNotFoundError if sample file is missing.

import json
import platform
from pathlib import Path
from typing import Dict, List, Any

from models import AppInfo, compute_risk

DATA_FILE = Path("data") / "sample_apps.json"

# Embedded fallback sample data (used if JSON file not found)
EMBEDDED_SAMPLE_APPS: List[dict] = [
    {
        "package_name": "com.example.spyapp",
        "app_name": "Screen Mirror Pro",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CALL_LOG",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_PHONE_STATE",
            "android.permission.INTERNET",
        ],
        "is_system_app": False,
        "has_launcher_icon": False,
        "installed_from_play_store": False,
        "uses_accessibility_service": True,
        "uses_media_projection": True,
        "has_overlay_permission": True,
        "foreground_service_usage_score": 0.9,
        "background_network_usage_score": 0.85,
    },
    {
        "package_name": "com.google.android.youtube",
        "app_name": "YouTube",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WAKE_LOCK",
        ],
        "is_system_app": False,
        "has_launcher_icon": True,
        "installed_from_play_store": True,
        "uses_accessibility_service": False,
        "uses_media_projection": False,
        "has_overlay_permission": False,
        "foreground_service_usage_score": 0.3,
        "background_network_usage_score": 0.4,
    },
    {
        "package_name": "com.example.supportapp",
        "app_name": "Remote Support Helper",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "is_system_app": False,
        "has_launcher_icon": True,
        "installed_from_play_store": True,
        "uses_accessibility_service": True,
        "uses_media_projection": True,
        "has_overlay_permission": True,
        "foreground_service_usage_score": 0.7,
        "background_network_usage_score": 0.6,
    },
    {
        "package_name": "com.whatsapp",
        "app_name": "WhatsApp",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
        ],
        "is_system_app": False,
        "has_launcher_icon": True,
        "installed_from_play_store": True,
        "uses_accessibility_service": False,
        "uses_media_projection": False,
        "has_overlay_permission": False,
        "foreground_service_usage_score": 0.4,
        "background_network_usage_score": 0.5,
    },
    {
        "package_name": "com.android.systemui",
        "app_name": "System UI",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        ],
        "is_system_app": True,
        "has_launcher_icon": False,
        "installed_from_play_store": False,
        "uses_accessibility_service": False,
        "uses_media_projection": False,
        "has_overlay_permission": False,
        "foreground_service_usage_score": 0.2,
        "background_network_usage_score": 0.1,
    },
]


def _load_from_json() -> List[dict]:
    """
    Load sample data from JSON if it exists.
    If not, return embedded sample data instead.
    """
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"[SpyShield] Loaded {len(data)} apps from {DATA_FILE}")
            return data
        except Exception as exc:
            print(f"[SpyShield] Error reading {DATA_FILE}: {exc}. Using embedded sample data.")
            return EMBEDDED_SAMPLE_APPS
    else:
        print(f"[SpyShield] Sample data file not found: {DATA_FILE}. Using embedded sample data.")
        return EMBEDDED_SAMPLE_APPS


def _load_from_windows_registry() -> List[dict]:
    """
    Try to load installed apps from Windows registry.
    If anything fails, fall back to JSON / embedded sample (no exceptions).
    """
    try:
        from scanner_windows import get_installed_apps_windows

        print("[SpyShield] Detected Windows OS; scanning installed applications...")
        raw_list = get_installed_apps_windows()
        print(f"[SpyShield] Found {len(raw_list)} installed applications in registry.")
        if not raw_list:
            print("[SpyShield] Registry scan returned no apps, falling back to sample data.")
            return _load_from_json()
        return raw_list
    except Exception as exc:
        print("[SpyShield] Failed to scan Windows apps; falling back to sample data.")
        print("Error:", exc)
        return _load_from_json()


def load_apps() -> Dict[str, dict]:
    """
    Main entry: load apps for the dashboard / Streamlit app.

    - On Windows: attempts registry scan, with safe fallback.
    - On other OS (Linux/macOS/Streamlit Cloud): uses sample data only.
    - NEVER raises FileNotFoundError if JSON is missing.
    """
    system = platform.system().lower()

    if system == "windows":
        raw_list = _load_from_windows_registry()
    else:
        print(f"[SpyShield] OS={system}. Using sample data (JSON or embedded).")
        raw_list = _load_from_json()

    apps: Dict[str, dict] = {}
    for raw in raw_list:
        app = AppInfo.from_dict(raw)
        score, level, reasons = compute_risk(app)

        info: Dict[str, Any] = app.to_dict()
        info["risk_score"] = score
        info["risk_level"] = level
        info["risk_reasons"] = reasons

        # Pass through extra metadata if present
        for extra_key in ("publisher", "install_location"):
            if extra_key in raw:
                info[extra_key] = raw[extra_key]

        apps[app.package_name] = info

    return apps


def save_apps(apps: Dict[str, dict]) -> None:
    """
    Optional helper: save current app data back to JSON (without risk fields).
    Not used by Streamlit, but kept for completeness.
    """
    cleaned: List[dict] = []
    for _, info in apps.items():
        d = dict(info)
        d.pop("risk_score", None)
        d.pop("risk_level", None)
        d.pop("risk_reasons", None)
        cleaned.append(d)

    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=4, ensure_ascii=False)
    print(f"[SpyShield] Saved {len(cleaned)} apps to {DATA_FILE}")
