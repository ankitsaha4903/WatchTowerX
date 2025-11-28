# storage.py
#
# Final, Streamlit-safe storage layer.
# - On Windows (local): tries to scan installed apps via registry (scanner_windows.py).
# - On all other OS (Linux/macOS/Streamlit Cloud): uses embedded sample data.
# - NO file access at all. NO FileNotFoundError possible.

import platform
from typing import Dict, List, Any

from models import AppInfo, compute_risk

# Embedded sample data used on non-Windows (e.g. Streamlit Cloud) or as fallback.
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


def _load_from_windows_registry() -> List[dict]:
    """
    Try to load installed apps from Windows registry.
    If anything fails, fall back to embedded sample data.
    """
    try:
        from scanner_windows import get_installed_apps_windows

        print("[SpyShield] Detected Windows OS; scanning installed applications...")
        raw_list = get_installed_apps_windows()
        print(f"[SpyShield] Found {len(raw_list)} installed applications in registry.")
        if not raw_list:
            print("[SpyShield] Registry scan returned no apps, using embedded sample data.")
            return EMBEDDED_SAMPLE_APPS
        return raw_list
    except Exception as exc:
        print("[SpyShield] Failed to scan Windows apps; using embedded sample data.")
        print("Error:", exc)
        return EMBEDDED_SAMPLE_APPS


def load_apps() -> Dict[str, dict]:
    """
    Main entry: load apps for the dashboard / Streamlit app.

    - On Windows: attempts registry scan, with safe fallback.
    - On other OS (Linux/macOS/Streamlit Cloud): uses embedded sample data only.
    """
    system = platform.system().lower()

    if system == "windows":
        raw_list = _load_from_windows_registry()
    else:
        print(f"[SpyShield] OS={system}. Using embedded sample data only.")
        raw_list = EMBEDDED_SAMPLE_APPS

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
