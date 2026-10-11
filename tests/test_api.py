"""API behaviour and security controls."""
import pytest
from fastapi.testclient import TestClient

from ssmf.api import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "t.db"), mode="rules", api_key="s3cret")
    with TestClient(app) as c:
        yield c


H = {"X-SSMF-Key": "s3cret"}


def ev(i=0, **kw):
    base = {"function_name": "payment-process", "caller": "external", "source_ip": "10.1.0.1",
            "status_code": 200, "duration_ms": 120.0, "payload_size_bytes": 600, "timestamp": 1_700_000_000.0 + i}
    base.update(kw)
    return base


def test_ingest_requires_api_key(client):
    assert client.post("/api/v1/events", json=[ev()]).status_code == 401
    assert client.post("/api/v1/events", json=[ev()], headers={"X-SSMF-Key": "wrong"}).status_code == 401
    assert client.post("/api/v1/events", json=[ev()], headers=H).status_code == 200


def test_reset_requires_api_key(client):
    assert client.post("/api/v1/admin/reset").status_code == 401
    assert client.post("/api/v1/admin/reset", headers=H).status_code == 200


@pytest.mark.parametrize("field,value", [
    ("function_name", "<script>alert(1)</script>"),
    ("function_name", 'x"} 1\nssmf_evil 1'),
    ("caller", "a b"),
    ("source_ip", "1.2.3.4; DROP TABLE events"),
    ("status_code", 99),
    ("duration_ms", -5),
    ("payload_size_bytes", -1),
])
def test_untrusted_fields_are_validated(client, field, value):
    r = client.post("/api/v1/events", json=[ev(**{field: value})], headers=H)
    assert r.status_code == 422


def test_batch_size_limit(client):
    r = client.post("/api/v1/events", json=[ev(i) for i in range(1001)], headers=H)
    assert r.status_code == 413


def test_oversized_body_rejected(client):
    r = client.post("/api/v1/events", content=b"x" * 1_100_000, headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_flood_produces_one_folded_alert_and_stats(client):
    batch = [ev(i * 0.01, source_ip="203.0.113.9", function_name="data-export", payload_size_bytes=15000, duration_ms=300)
             for i in range(200)]
    r = client.post("/api/v1/events", json=batch, headers=H)
    assert r.status_code == 200 and r.json()["accepted"] == 200
    alerts = client.get("/api/v1/alerts").json()
    floods = [a for a in alerts if a["rule"] == "INVOCATION_FLOOD"]
    assert len(floods) == 1 and floods[0]["suppressed"] > 100 and floods[0]["severity"] == "high"
    stats = client.get("/api/v1/stats").json()
    assert stats["total_events"] == 200 and stats["flagged_events"] > 100
    assert stats["by_rule"][0]["rule"] == "INVOCATION_FLOOD" and stats["engine"]["mode"] == "rules"


def test_alert_filtering_and_validation(client):
    assert client.get("/api/v1/alerts?severity=bogus").status_code == 422
    assert client.get("/api/v1/alerts?limit=0").status_code == 422
    assert client.get("/api/v1/alerts?severity=high").status_code == 200


def test_unauthorized_call_alert(client):
    client.post("/api/v1/events", json=[ev(caller="image-resize")], headers=H)
    a = client.get("/api/v1/alerts").json()
    assert a and a[0]["rule"] == "UNAUTHORIZED_CALL"


def test_metrics_format(client):
    client.post("/api/v1/events", json=[ev(), ev(1, caller="image-resize")], headers=H)
    text = client.get("/metrics").text
    assert 'ssmf_events_total{function="payment-process"} 2' in text
    assert 'ssmf_alerts_total{rule="UNAUTHORIZED_CALL",severity="high"} 1' in text
    assert "ssmf_ml_ready 0" in text


def test_dashboard_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "SSMF" in r.text
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/health").json()["status"] == "ok"


def test_policy_endpoint(client):
    p = client.get("/api/v1/policy").json()
    assert p["functions"]["payment-process"]["allowed_callers"] == ["auth-check", "external"]


def test_open_ingest_when_no_key_configured(tmp_path):
    app = create_app(db_path=str(tmp_path / "o.db"), mode="rules", api_key="")
    with TestClient(app) as c:
        assert c.post("/api/v1/events", json=[ev()]).status_code == 200
