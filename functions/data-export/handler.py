"""data-export: returns N synthetic rows; cost and response size grow with `rows`."""
import json
import os
import random
import time

from ssmf_sdk import monitored


def _io(low_ms, high_ms):
    """Stand-in for a downstream DB/API call. Demo only: set SSMF_DEMO_IO=0 to disable."""
    if os.environ.get("SSMF_DEMO_IO", "1") == "1":
        time.sleep(random.uniform(low_ms, high_ms) / 1000.0)


@monitored("data-export")
def handle(event, context):
    _io(30, 50)
    try:
        data = json.loads(event.body or b"{}")
        rows = max(1, min(int(data.get("rows", 50)), 2000))
    except (ValueError, TypeError):
        return {"statusCode": 400, "body": "bad request"}
    out = [{"id": i, "value": (i * 7919) % 10007} for i in range(rows)]
    return {"statusCode": 200, "body": json.dumps(out)}
