# notifier.py

import smtplib
from email.mime.text import MIMEText
from config import EMAIL_ALERTS
from db import get_policies


def send_alert(subject: str, body: str):
    """
    Sends an email alert to the address configured in Policies (alert_email).
    Uses SMTP settings from config.EMAIL_ALERTS.
    Only works if EMAIL_ALERTS["enabled"] is True.
    """
    if not EMAIL_ALERTS.get("enabled", False):
        # SMTP not enabled in config
        return

    policies = get_policies()
    to_addr = policies.get("alert_email") or EMAIL_ALERTS.get("default_to_addr")
    if not to_addr:
        # No recipient configured
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ALERTS["from_addr"]
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(EMAIL_ALERTS["smtp_server"], EMAIL_ALERTS["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_ALERTS["username"], EMAIL_ALERTS["password"])
            server.send_message(msg)
    except Exception as e:
        print(f"[Notifier] Failed to send email alert: {e}")
