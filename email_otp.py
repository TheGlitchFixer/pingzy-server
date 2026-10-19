"""Email OTP delivery.

Configuration via environment variables:
    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       e.g. 587
    SMTP_USER       sender address
    SMTP_PASSWORD   app password / API key
    SMTP_FROM       "SecureChat <noreply@example.com>"
    SMTP_USE_TLS    "1" (default) — STARTTLS

Alternatives (documented, not implemented here — swap `send_otp_email`):
  - SendGrid:   pip install sendgrid; use sendgrid.SendGridAPIClient
  - AWS SES:    pip install boto3; use ses.send_email
  - Mailgun:    POST to https://api.mailgun.net/v3/<domain>/messages
Any transactional provider works — the OTP logic is provider-agnostic.

For local development without SMTP, set SMTP_HOST="" and the OTP code
is printed to the server log (DEV ONLY — never in production).
"""
import logging
import os
import smtplib
from email.mime.text import MIMEText

log = logging.getLogger("securechat")


def _cfg():
    return {
        "host": os.environ.get("SMTP_HOST", ""),
        "port": int(os.environ.get("SMTP_PORT", "587")),
        "user": os.environ.get("SMTP_USER", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from": os.environ.get("SMTP_FROM", "SecureChat <noreply@securechat>"),
        "tls": os.environ.get("SMTP_USE_TLS", "1") == "1",
    }


def send_otp_email(to_email: str, code: str) -> bool:
    """Send the 6-digit OTP. Returns True on success."""
    cfg = _cfg()
    if not cfg["host"]:
        # DEV MODE: no SMTP configured — log the code so the developer
        # can complete registration. NEVER enable in production.
        log.warning("DEV MODE: OTP for %s is %s (configure SMTP_HOST "
                    "for production)", to_email, code)
        return True

    subject = "Your SecureChat verification code"
    body = (
        f"Your SecureChat verification code is:\n\n"
        f"    {code}\n\n"
        f"It expires in 10 minutes. If you didn't request this, ignore "
        f"this email.\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg["from"]
    msg["To"] = to_email
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            if cfg["tls"]:
                s.starttls()
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.sendmail(cfg["from"], [to_email], msg.as_string())
        log.info("OTP email sent to %s", to_email)
        return True
    except Exception:
        log.exception("failed to send OTP email to %s", to_email)
        return False
