"""Simple in-memory rate limiter (sliding window).

Defense-in-depth: prevents a single client/IP from flooding the relay.
Limits are intentionally generous for normal chat use; they only bite
on abuse or runaway clients.
"""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        # key -> deque[timestamps]
        self._hits = defaultdict(deque)
        # (max_requests, window_seconds) per bucket name
        self._rules = {
            # websocket messages per connection
            "ws_msg": (120, 60),        # 120 msgs / minute
            "ws_register": (10, 600),   # 10 registrations / 10 min / IP
            "ws_auth": (30, 600),       # 30 auth attempts / 10 min / IP
            # http
            "http_upload": (20, 3600),  # 20 file uploads / hour / user
            "http_download": (300, 3600),
            "http_health": (60, 60),
            # email OTP
            "otp_request": (3, 3600),     # 3 OTP requests / hour / email
            "otp_request_ip": (10, 3600),  # 10 OTP requests / hour / IP
        }

    def _prune(self, dq, window):
        cutoff = time.time() - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def allow(self, bucket, key):
        """Return True if the action is allowed, False if rate-limited."""
        max_req, window = self._rules[bucket]
        dq = self._hits[(bucket, key)]
        self._prune(dq, window)
        if len(dq) >= max_req:
            return False
        dq.append(time.time())
        return True

    def cleanup(self):
        """Drop stale buckets (call periodically)."""
        now = time.time()
        stale = []
        for k, dq in self._hits.items():
            _, window = self._rules[k[0]]
            self._prune(dq, window)
            if not dq and now - (dq[-1] if dq else 0) > 3600:
                stale.append(k)
        for k in stale:
            del self._hits[k]
