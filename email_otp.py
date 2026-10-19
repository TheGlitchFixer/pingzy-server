"""Email OTP delivery via Resend HTTP API.

Configuration via environment variables:
    RESEND_API_KEY   e.g. re_xxxxxxxxxxxx
    EMAIL_FROM       e.g. "Pingzy <onboarding@resend.dev>"

Railway blocks outbound SMTP, so we use Resend's HTTPS API instead.
For local development without a key, set RESEND_API_KEY="" and the OTP
code is printed to the server log (DEV ONLY — never in production).
"""
import json
import logging
import os
import urllib.request

log = logging.getLogger("securechat")


def send_otp_email(to_email: str, code: str) -> bool:
    """Send the 6-digit OTP via Resend. Returns True on success."""
    api_key = os.environ.get("RESEND_API_KEY", "")
    from_addr = os.environ.get("EMAIL_FROM", "Pingzy <onboarding@resend.dev>")
    if not api_key:
        # DEV MODE: no API key configured — log the code so the developer
        # can complete registration. NEVER enable in production.
        log.warning("DEV MODE: OTP for %s is %s (configure RESEND_API_KEY "
                    "for production)", to_email, code)
        return True

    subject = "Your Pingzy verification code"
    body = (
        f"Your Pingzy verification code is:\n\n"
        f"    {code}\n\n"
        f"It expires in 10 minutes. If you didn't request this, ignore "
        f"this email.\n"
    )
    payload = json.dumps({
        "from": from_addr,
        "to": [to_email],
        "subject": subject,
        "text": body,
    }).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if 200 <= resp.status < 300:
                log.info("OTP email sent to %s", to_email)
                return True
            log.error("Resend returned HTTP %s for %s", resp.status, to_email)
            return False
    except Exception:
        log.exception("failed to send OTP email to %s", to_email)
        return False
