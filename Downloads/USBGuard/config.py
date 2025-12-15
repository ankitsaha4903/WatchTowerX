# config.py

import os

# Path to SQLite database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "usb_guard.db")

# Agent settings
SCAN_INTERVAL_SECONDS = 5  # how often to scan for USB devices
LOG_LEVEL = "INFO"

# Default policies (these can be overridden from the dashboard)
DEFAULT_POLICIES = {
    "default_usb_action": "block_unknown",  # options: allow_all, block_unknown
    "log_file_events": "true",
    "alert_on_block": "false",  # if true, will try to send email via notifier
    "alert_email": "",          # admin/login email for alerts (set in Policies page)
}

# Email alert config (SMTP settings)
EMAIL_ALERTS = {
    "enabled": False,                # set True when SMTP is correctly configured
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "username": "your_email@example.com",
    "password": "your_password",
    "from_addr": "your_email@example.com",
    # optional fallback if alert_email not set in policies
    "default_to_addr": "security_admin@example.com",
}
