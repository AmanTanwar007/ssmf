import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest  # noqa: E402

from ssmf.config import load_policy  # noqa: E402
from ssmf.models import Event  # noqa: E402


@pytest.fixture(scope="session")
def policy():
    return load_policy()


def make_event(fn="payment-process", t=0.0, caller="external", ip="10.1.0.1", status=200, dur=120.0, size=600):
    return Event(invocation_id="t", timestamp=t, function_name=fn, caller=caller, source_ip=ip,
                 status_code=status, duration_ms=dur, payload_size_bytes=size)
