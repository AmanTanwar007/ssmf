"""ML detector: learning period, all algorithms, hybrid behaviour."""
import dataclasses

import pytest
import simulator
from conftest import make_event

from ssmf.engine import DetectionEngine


def ml_policy(policy, algorithm):
    ml = dataclasses.replace(policy.detection.ml, algorithm=algorithm)
    return dataclasses.replace(policy, detection=dataclasses.replace(policy.detection, ml=ml))


def test_model_is_not_ready_before_warmup_and_ready_after(policy):
    eng = DetectionEngine(policy, mode="hybrid")
    eng.process_batch(simulator.generate(300, seed=1))
    assert not eng.ml.ready and eng.info()["ml_warmup_needed"] == policy.detection.ml.warmup_events
    eng.process_batch(simulator.generate(3000, seed=2))
    assert eng.ml.ready and eng.info()["ml_threshold"] is not None


@pytest.mark.parametrize("algorithm", ["lof", "iforest", "mahalanobis"])
def test_every_algorithm_trains_and_scores(policy, algorithm):
    eng = DetectionEngine(ml_policy(policy, algorithm), mode="ml")
    eng.warm_up(simulator.generate(3000, seed=3))
    assert eng.ml.ready
    dets = eng.process_batch(simulator.generate(500, seed=4, start=2_000_000_000.0))
    assert all(d.ml_score is not None for d in dets)


def test_lof_catches_a_brute_force_burst_without_rules(policy):
    eng = DetectionEngine(policy, mode="ml")
    eng.warm_up(simulator.generate(3000, seed=3))
    t = 2_000_000_000.0
    dets = [eng.process_event(make_event("auth-check", t + i * 0.1, ip="203.0.113.14", status=401, size=250, dur=20))
            for i in range(40)]
    assert any(d.flagged for d in dets[10:])
    assert all(h.rule == "ML_ANOMALY" for d in dets for h in d.hits)


def test_ml_only_finding_is_low_severity_but_corroboration_escalates(policy):
    eng = DetectionEngine(policy, mode="hybrid")
    eng.warm_up(simulator.generate(3000, seed=3))
    t = 2_000_000_000.0
    # Statistically odd but inside every explicit rule's limits: ML-only, ranked low.
    d = eng.process_event(make_event("data-export", t, size=50_000, dur=900, status=404))
    if d.flagged:
        assert d.rule_names == ["ML_ANOMALY"] and d.severity == "low"
    # Rule + ML agreeing escalates beyond the rule's own severity.
    both = [eng.process_event(make_event("payment-process", t + 1 + i * 0.01, ip="203.0.113.9", size=600_000, dur=900))
            for i in range(5)][-1]
    assert "PAYLOAD_ANOMALY" in both.rule_names and "ML_ANOMALY" in both.rule_names
    assert both.severity in ("high", "critical")


def test_rules_mode_never_trains_a_model(policy):
    eng = DetectionEngine(policy, mode="rules")
    eng.warm_up(simulator.generate(3000, seed=3))
    assert not eng.ml.ready and not eng.use_ml


def test_ml_persistence_requires_repeated_flags_from_the_same_source(policy):
    """Attacks are bursts; isolated model flags (the false-positive pattern) must not alert."""
    eng = DetectionEngine(policy, mode="hybrid")
    a = make_event(t=1000.0, ip="10.1.0.1")
    assert eng._ml_persistent(a) is False                                   # first flag from this source
    assert eng._ml_persistent(make_event(t=1002.0, ip="10.1.0.2")) is False  # another source: independent
    assert eng._ml_persistent(make_event(t=1003.0, ip="10.1.0.1")) is True   # second flag inside the window
    assert eng._ml_persistent(make_event(t=1100.0, ip="10.1.0.1")) is False  # window expired: starts over
