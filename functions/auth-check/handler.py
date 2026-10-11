"""auth-check: verifies credentials and returns a (demo) token."""
import hashlib
import hmac
import json
import os
import random
import time

from ssmf_sdk import monitored

# DEMO ONLY - a real function would verify against an identity provider / user store.
_USERS = {
    "alice": hashlib.sha256(b"alice-pass").hexdigest(),
    "bob": hashlib.sha256(b"bob-pass").hexdigest(),
}


def _io(low_ms, high_ms):
    """Stand-in for a downstream DB/API call. Demo only: set SSMF_DEMO_IO=0 to disable."""
    if os.environ.get("SSMF_DEMO_IO", "1") == "1":
        time.sleep(random.uniform(low_ms, high_ms) / 1000.0)


@monitored("auth-check")
def handle(event, context):
    _io(8, 14)
    try:
        data = json.loads(event.body or b"{}")
    except ValueError:
        return {"statusCode": 400, "body": "bad request"}
    expected = _USERS.get(str(data.get("user")))
    given = hashlib.sha256(str(data.get("password", "")).encode()).hexdigest()
    if expected and hmac.compare_digest(expected, given):
        return {"statusCode": 200, "body": json.dumps({"token": "demo-token"})}
    return {"statusCode": 401, "body": "invalid credentials"}
