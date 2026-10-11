"""image-resize: stand-in for CPU-bound work; cost grows with the X-Quality header.

The cap (500k passes) is deliberately generous: an unbounded or loosely bounded
client-controlled work factor is the classic resource-abuse surface SSMF watches.
"""
import hashlib
import os
import random
import time

from ssmf_sdk import monitored


def _io(low_ms, high_ms):
    """Stand-in for a downstream DB/API call. Demo only: set SSMF_DEMO_IO=0 to disable."""
    if os.environ.get("SSMF_DEMO_IO", "1") == "1":
        time.sleep(random.uniform(low_ms, high_ms) / 1000.0)


@monitored("image-resize")
def handle(event, context):
    _io(20, 35)
    headers = {str(k).lower(): v for k, v in (event.headers or {}).items()}
    try:
        rounds = max(1, min(int(headers.get("x-quality", "10")), 500_000))
    except ValueError:
        return {"statusCode": 400, "body": "bad quality"}
    digest = hashlib.sha256(event.body or b"").digest()
    for _ in range(rounds):                      # simulated processing passes
        digest = hashlib.sha256(digest).digest()
    return {"statusCode": 200, "body": digest.hex()[:16]}
