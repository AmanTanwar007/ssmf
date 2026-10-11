"""notify-user: queues a notification (demo: just validates and acknowledges)."""
import json
import os
import random
import time

from ssmf_sdk import monitored


def _io(low_ms, high_ms):
    """Stand-in for a downstream DB/API call. Demo only: set SSMF_DEMO_IO=0 to disable."""
    if os.environ.get("SSMF_DEMO_IO", "1") == "1":
        time.sleep(random.uniform(low_ms, high_ms) / 1000.0)


@monitored("notify-user")
def handle(event, context):
    _io(10, 20)
    try:
        data = json.loads(event.body or b"{}")
        user, message = str(data["user"]), str(data["message"])[:500]
    except (ValueError, KeyError, TypeError):
        return {"statusCode": 400, "body": "user and message required"}
    return {"statusCode": 200, "body": json.dumps({"queued": True, "user": user, "chars": len(message)})}
