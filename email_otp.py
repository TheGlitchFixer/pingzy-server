"""Email OTP delivery via Brevo HTTP API.

Configuration via environment variables:
    BREVO_API_KEY   e.g. xkeysib-xxxxxxxxxxxx
    EMAIL_FROM      e.g. "Pingzy <noreply@pingzy.app>"

Railway blocks outbound SMTP, and Resend blocks Railway via Cloudflare,
so we use Brevo's HTTPS API instead.
For local development without a key, set BREVO_API_KEY="" and the OTP
code is printed to the server log (DEV ONLY — never in production).
"""
import json
import logging
import os
import urllib.request
import urllib.error

log = logging.getLogger("securechat")


def send_otp_email(to_email: str, code: str) -> bool:
    """Send the 6-digit OTP via Brevo. Returns True on success."""
    api_key = os.environ.get("BREVO_API_KEY", "")
    from_addr = os.environ.get("EMAIL_FROM", "Pingzy <noreply@pingzy.app>")
    # Parse "Name <email>" format
    if "<" in from_addr and ">" in from_addr:
        name = from_addr.split("<")[0].strip()
        email = from_addr.split("<")[1].split(">")[0].strip()
    else:
        name = "Pingzy"
        email = from_addr.strip()

    if not api_key:
        # DEV MODE: no API key configured — log the code so the developer
        # can complete registration. NEVER enable in production.
        log.warning("DEV MODE: OTP for %s is %s (configure BREVO_API_KEY "
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
        "sender": {"name": name, "email": email},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": body,
    }).encode()
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=payload,
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if 200 <= resp.status < 300:
                log.info("OTP email sent to %s", to_email)
                return True
            body = resp.read().decode()[:500]
            log.error("Brevo returned HTTP %s for %s: %s",
                      resp.status, to_email, body)
            return False
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode()[:500]
        except Exception:
            body = "<no body>"
        log.error("Brevo HTTP %s for %s: %s", e.code, to_email, body)
        return False
    except Exception:
        log.exception("failed to send OTP email to %s", to_email)
        return False
