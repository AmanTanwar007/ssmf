"""Rule engine behaviour, including regressions for attribution and baseline poisoning."""
import simulator
from conftest import make_event

from ssmf.engine import DetectionEngine


def warmed(policy, mode="rules", n=2500, seed=5):
    eng = DetectionEngine(policy, mode=mode)
    base = simulator.generate(n, seed=seed)
    eng.warm_up(base)
    return eng, base[-1].timestamp + 30


def rules_of(det):
    return set(det.rule_names)


def test_unauthorized_call_flagged(policy):
    eng, t = warmed(policy)
    d = eng.process_event(make_event("payment-process", t, caller="image-resize"))
    assert "UNAUTHORIZED_CALL" in rules_of(d) and d.severity in ("high", "critical")


def test_allowed_call_not_flagged(policy):
    eng, t = warmed(policy)
    d = eng.process_event(make_event("payment-process", t, caller="auth-check"))
    assert "UNAUTHORIZED_CALL" not in rules_of(d)


def test_clean_traffic_has_very_low_false_positive_rate(policy):
    eng, _ = warmed(policy)
    test = simulator.generate(4000, seed=99, start=2_000_000_000.0)
    dets = eng.process_batch(test)
    fpr = sum(d.flagged for d in dets) / len(dets)
    assert fpr < 0.005, f"false-positive rate too high: {fpr:.3%}"


def test_source_flood_flagged(policy):
    eng, t = warmed(policy)
    dets = [eng.process_event(make_event("data-export", t + i * 0.005, ip="203.0.113.9", size=15000, dur=300))
            for i in range(120)]
    assert any("INVOCATION_FLOOD" in rules_of(d) for d in dets)


def test_legitimate_caller_not_flagged_during_someone_elses_flood(policy):
    """Regression: collateral damage. A flood from one source must not flag other clients."""
    eng, t = warmed(policy)
    for i in range(300):
        eng.process_event(make_event("data-export", t + i * 0.005, ip="203.0.113.9", size=15000, dur=300))
    legit = eng.process_event(make_event("data-export", t + 1.6, ip="10.1.0.7", size=15000, dur=300))
    assert "INVOCATION_FLOOD" not in rules_of(legit)


def test_auth_bruteforce_flagged(policy):
    eng, t = warmed(policy)
    dets = [eng.process_event(make_event("auth-check", t + i * 0.2, ip="203.0.113.14", status=401, size=250, dur=20))
            for i in range(15)]
    assert "AUTH_BRUTEFORCE" in rules_of(dets[-1])
    assert "AUTH_BRUTEFORCE" not in rules_of(dets[0])


def test_payload_over_policy_cap_flagged(policy):
    eng, t = warmed(policy)
    d = eng.process_event(make_event("auth-check", t, size=5_000_000, dur=25))
    assert "PAYLOAD_ANOMALY" in rules_of(d)


def test_statistical_payload_outlier_flagged_below_cap(policy):
    eng, t = warmed(policy)
    d = eng.process_event(make_event("data-export", t, size=400_000, dur=300))   # ~27x norm, under 1 MB cap
    assert "PAYLOAD_ANOMALY" in rules_of(d)


def test_duration_outlier_flagged(policy):
    eng, t = warmed(policy)
    d = eng.process_event(make_event("image-resize", t, size=120_000, dur=4000))
    assert "DURATION_ANOMALY" in rules_of(d)


def test_error_spike_flagged(policy):
    eng, t = warmed(policy)
    dets = [eng.process_event(make_event("notify-user", t + i * 0.3, ip=f"10.1.0.{i+1}", status=500, size=300, dur=40))
            for i in range(14)]
    assert "ERROR_SPIKE" in rules_of(dets[-1])


def test_flagged_events_do_not_poison_the_baseline(policy):
    eng, t = warmed(policy)
    before = eng.state.payload_stats["data-export"].n
    for i in range(50):
        eng.process_event(make_event("data-export", t + i, size=900_000, dur=300, ip=f"10.1.1.{i}"))
    assert eng.state.payload_stats["data-export"].n == before


def test_multiple_rules_raise_risk_and_escalate_severity(policy):
    eng, t = warmed(policy)
    d = eng.process_event(make_event("auth-check", t, caller="notify-user", size=5_000_000, dur=25))
    assert {"UNAUTHORIZED_CALL", "PAYLOAD_ANOMALY"} <= rules_of(d)
    assert d.risk_score >= 75 and d.severity == "critical"


def test_busy_legitimate_client_not_blamed_for_a_flood_it_did_not_cause(policy):
    """Regression (found via dashboard testing): a busy-but-normal client must not be flagged as a flooder
    just because the function it calls is over its volume limit."""
    eng, t = warmed(policy)
    for i in range(18):                                       # this client is busy elsewhere: src_count builds up
        eng.process_event(make_event("notify-user", t + i * 0.01, ip="10.1.0.7", size=300, dur=40))
    for i in range(300):                                      # someone else floods data-export
        eng.process_event(make_event("data-export", t + 1 + i * 0.005, ip="203.0.113.9", size=15000, dur=300))
    legit = eng.process_event(make_event("data-export", t + 2.6, ip="10.1.0.7", size=15000, dur=300))
    assert "INVOCATION_FLOOD" not in rules_of(legit)
