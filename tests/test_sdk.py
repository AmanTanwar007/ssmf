"""SDK behaviour: instrumentation, caller identity, resilience."""
import time
import types

import pytest
from ssmf_sdk import Reporter, caller_headers, monitored


def make_event(body=b"{}", headers=None):
    return types.SimpleNamespace(body=body, headers=headers or {})


def collector():
    got = []
    return got, Reporter(sink=got.extend, sync=True)


def test_reports_status_duration_payload_and_defaults():
    got, rep = collector()

    @monitored("demo-fn", reporter=rep)
    def handle(event, context):
        time.sleep(0.01)
        return {"statusCode": 201, "body": "ok"}

    out = handle(make_event(b"x" * 321, {"X-Forwarded-For": "198.51.100.7, 10.0.0.1"}), None)
    assert out["statusCode"] == 201                      # result is passed through untouched
    e = got[0]
    assert e["function_name"] == "demo-fn" and e["status_code"] == 201
    assert e["payload_size_bytes"] == 321 and e["source_ip"] == "198.51.100.7"
    assert e["caller"] == "external" and e["duration_ms"] >= 10


def test_exception_is_reported_as_500_and_reraised():
    got, rep = collector()

    @monitored("boom", reporter=rep)
    def handle(event, context):
        raise ValueError("bug")

    with pytest.raises(ValueError):
        handle(make_event(), None)
    assert got[0]["status_code"] == 500


def test_monitor_outage_never_breaks_the_function():
    rep = Reporter(url="http://127.0.0.1:1", sync=True, api_key="k")     # nothing listens on port 1

    @monitored("resilient", reporter=rep)
    def handle(event, context):
        return {"statusCode": 200, "body": "fine"}

    assert handle(make_event(), None)["body"] == "fine"
    assert rep.failures == 1


def test_untrusted_header_values_are_sanitised():
    got, rep = collector()

    @monitored("f", reporter=rep)
    def handle(event, context):
        return {"statusCode": 200}

    handle(make_event(headers={"X-Forwarded-For": "1.2.3.4\nX: <script>", "X-Call-Id": "a b;c"}), None)
    assert all(c.isalnum() or c in "_.:-" for c in got[0]["source_ip"] + got[0]["invocation_id"])


def test_unsigned_mode_trusts_caller_header(monkeypatch):
    monkeypatch.delenv("SSMF_CALLER_SECRET", raising=False)
    got, rep = collector()

    @monitored("payment-process", reporter=rep)
    def handle(event, context):
        return {"statusCode": 200}

    handle(make_event(headers={"X-Caller-Function": "auth-check"}), None)
    assert got[0]["caller"] == "auth-check"


def test_signed_caller_is_accepted_and_forged_caller_is_marked_spoofed(monkeypatch):
    monkeypatch.setenv("SSMF_CALLER_SECRET", "topsecret")
    got, rep = collector()

    @monitored("payment-process", reporter=rep)
    def handle(event, context):
        return {"statusCode": 200}

    handle(make_event(headers=caller_headers("auth-check")), None)                       # legitimate
    handle(make_event(headers={"X-Caller-Function": "auth-check"}), None)                # forged: no signature
    stale = caller_headers("auth-check")
    stale["X-Caller-Ts"] = str(int(time.time()) - 3600)
    handle(make_event(headers=stale), None)                                              # replayed/stale
    assert [e["caller"] for e in got] == ["auth-check", "spoofed:auth-check", "spoofed:auth-check"]


def test_queue_overflow_sheds_load_instead_of_blocking():
    rep = Reporter(sink=lambda b: time.sleep(5), max_queue=5, flush_interval=0.01)
    t0 = time.time()
    for i in range(200):
        rep.emit({"i": i})
    assert time.time() - t0 < 1.0 and rep.dropped > 100


def test_async_reporter_batches_and_flushes():
    batches = []
    rep = Reporter(sink=batches.append, batch_size=10, flush_interval=0.05)
    for i in range(25):
        rep.emit({"i": i})
    assert rep.flush(3.0)
    assert sum(len(b) for b in batches) == 25 and max(len(b) for b in batches) <= 10
