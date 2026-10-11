import pytest
from conftest import make_event

from ssmf.alerting import AlertManager
from ssmf.config import AlertSettings, PolicyError, parse_policy
from ssmf.models import Detection, RuleHit
from ssmf.storage import Store


class Capture:
    def __init__(self):
        self.sent = []

    def send(self, alert):
        self.sent.append(alert)


class Boom:
    def send(self, alert):
        raise RuntimeError("webhook down")


def flagged(t, ip="203.0.113.9"):
    d = Detection(event=make_event("data-export", t, ip=ip))
    d.hits = [RuleHit("INVOCATION_FLOOD", "high", "too many")]
    d.flagged, d.risk_score, d.severity = True, 40, "high"
    return d


def test_cooldown_folds_duplicates_into_the_open_alert():
    cap = Capture()
    am = AlertManager(AlertSettings(cooldown_seconds=30), sinks=[cap])
    first = am.process(flagged(0.0))[0]
    assert all(am.process(flagged(i)) == [] for i in range(1, 20))
    assert first.suppressed == 19 and len(cap.sent) == 1
    assert [a.alert_id for a in am.drain_updated()] == [first.alert_id]
    assert len(am.process(flagged(31.0))) == 1                       # cooldown elapsed -> new alert
    assert len(am.process(flagged(5.0, ip="203.0.113.99"))) == 1     # different source is not folded


def test_each_distinct_rule_gets_its_own_alert():
    """Regression: a brute force must not be hidden behind an earlier flood alert from the same source."""
    am = AlertManager(AlertSettings(cooldown_seconds=30), sinks=[])
    flood = flagged(0.0)
    assert [a.rule for a in am.process(flood)] == ["INVOCATION_FLOOD"]
    both = flagged(1.0)
    both.hits = [RuleHit("INVOCATION_FLOOD", "high", "flood"), RuleHit("AUTH_BRUTEFORCE", "high", "brute")]
    assert [a.rule for a in am.process(both)] == ["AUTH_BRUTEFORCE"]      # flood folded, brute force is new


def test_ml_only_alert_is_suppressed_when_an_explicit_rule_fired():
    am = AlertManager(AlertSettings(), sinks=[])
    d = flagged(0.0)
    d.hits = [RuleHit("UNAUTHORIZED_CALL", "high", "x"), RuleHit("ML_ANOMALY", "low", "y")]
    assert [a.rule for a in am.process(d)] == ["UNAUTHORIZED_CALL"]
    only_ml = flagged(100.0, ip="1.1.1.1")
    only_ml.hits = [RuleHit("ML_ANOMALY", "low", "y")]
    assert [a.rule for a in am.process(only_ml)] == ["ML_ANOMALY"]


def test_dead_sink_never_breaks_alerting():
    cap = Capture()
    am = AlertManager(AlertSettings(), sinks=[Boom(), cap])
    assert len(am.process(flagged(0.0))) == 1 and len(cap.sent) == 1


def test_unflagged_detection_makes_no_alert():
    am = AlertManager(AlertSettings(), sinks=[])
    assert am.process(Detection(event=make_event())) == []


def test_store_prunes_to_max_events():
    store = Store(":memory:", max_events=1000)
    dets = []
    for i in range(2500):
        d = Detection(event=make_event(t=float(i)))
        dets.append(d)
    store.insert_detections(dets)
    assert store.stats()["total_events"] == 1000


def test_store_stats_shape():
    store = Store(":memory:")
    store.insert_detections([Detection(event=make_event(t=float(i))) for i in range(30)])
    s = store.stats()
    assert s["total_events"] == 30 and s["by_function"][0]["function_name"] == "payment-process" and s["timeseries"]


@pytest.mark.parametrize("bad", [
    {},                                                    # no functions
    {"functions": {"a": {"allowed_callers": []}}},         # empty caller list
    {"functions": {"a": {}}, "detection": {"mode": "magic"}},
    {"functions": {"a": {}}, "detection": {"ml": {"algorithm": "svm"}}},
    {"functions": {"a": {}}, "detection": {"ml": {"false_positive_target": 0.9}}},
])
def test_invalid_policies_are_rejected(bad):
    with pytest.raises(PolicyError):
        parse_policy(bad)


def test_valid_minimal_policy_gets_defaults():
    p = parse_policy({"functions": {"a": {"allowed_callers": ["external"]}}})
    assert p.detection.mode == "hybrid" and p.allowed_callers("a") == frozenset({"external"})
    assert p.allowed_callers("unknown-fn") == frozenset({"external"})
