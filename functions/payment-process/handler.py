"""payment-process: validates and "charges" an amount. Callable by clients and auth-check only."""
import hashlib
import json
import os
import random
import time

from ssmf_sdk import monitored


def _io(low_ms, high_ms):
    """Stand-in for a downstream DB/API call. Demo only: set SSMF_DEMO_IO=0 to disable."""
    if os.environ.get("SSMF_DEMO_IO", "1") == "1":
        time.sleep(random.uniform(low_ms, high_ms) / 1000.0)


@monitored("payment-process")
def handle(event, context):
    _io(25, 45)
    try:
        data = json.loads(event.body or b"{}")
        amount = float(data["amount"])
    except (ValueError, KeyError, TypeError):
        return {"statusCode": 400, "body": "amount required"}
    if not 0 < amount <= 10_000:
        return {"statusCode": 422, "body": "amount out of range"}
    receipt = hashlib.sha256(f"{data.get('user')}|{amount}".encode()).hexdigest()[:16]
    return {"statusCode": 200, "body": json.dumps({"receipt": receipt, "fee": round(amount * 0.02, 2)})}
