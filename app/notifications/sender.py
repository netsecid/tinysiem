import json
import logging
import smtplib
import ssl
import urllib.request
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger(__name__)
_SEV_ORDER = ["low", "medium", "high", "critical"]


def should_notify(severity: str) -> bool:
    sev = (severity or "").lower()
    min_sev = (settings.tinysiem_notify_min_sev or "high").lower()
    try:
        return _SEV_ORDER.index(sev) >= _SEV_ORDER.index(min_sev)
    except ValueError:
        return False


def send_email(alert: dict) -> None:
    if not settings.tinysiem_smtp_host or not settings.tinysiem_smtp_to:
        return
    try:
        subject = f"[TinySIEM] {alert.get('severity', '').upper()} alert: {alert.get('rule_name', '')}"
        body = (
            f"Alert ID:    {alert.get('alert_id')}\n"
            f"Rule:        {alert.get('rule_name')}\n"
            f"Severity:    {alert.get('severity')}\n"
            f"Source IP:   {alert.get('source_ip')}\n"
            f"Triggered:   {alert.get('triggered_at')}\n"
            f"MITRE:       {alert.get('mitre_tactic')} / {alert.get('mitre_technique')}\n\n"
            f"Summary: {alert.get('summary')}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.tinysiem_smtp_from or settings.tinysiem_smtp_user
        msg["To"] = settings.tinysiem_smtp_to
        recipients = [r.strip() for r in settings.tinysiem_smtp_to.split(",") if r.strip()]
        if settings.tinysiem_smtp_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                s.starttls(context=ctx)
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
        else:
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
    except Exception as exc:
        logger.error(f"Notification email failed: {exc}")


def send_webhook(alert: dict) -> None:
    if not settings.tinysiem_webhook_url:
        return
    try:
        payload = json.dumps({k: alert.get(k) for k in [
            "alert_id", "rule_name", "severity", "triggered_at",
            "source_ip", "summary", "mitre_tactic", "mitre_technique",
        ]}).encode()
        req = urllib.request.Request(
            settings.tinysiem_webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"Webhook delivered: {resp.status}")
    except Exception as exc:
        logger.error(f"Notification webhook failed: {exc}")


def notify(alert: dict) -> None:
    if not should_notify(alert.get("severity", "")):
        return
    send_email(alert)
    send_webhook(alert)
