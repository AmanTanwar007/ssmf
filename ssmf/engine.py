"""Detection engine: state -> rules -> ML -> scored Detection per event.

Modes
-----
rules   explicit policy/threshold rules only
ml      Isolation Forest only (rules still act as a guard that keeps flagged
        events out of the baseline, so the model is not trained on attacks)
hybrid  alert if either fires; agreement between the two raises the severity
"""
from __future__ import annotations

from typing import Iterable

from .config import Policy
from .ml import MLDetector
from .ml import features as ml_features
from .models import SEVERITIES, Detection, Event, RuleHit
from .rules import RULE_WEIGHTS, RuleEngine
from .state import SlidingCounter, StreamState

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _severity(hits: list) -> str:
    level = max(_SEV_RANK[h.severity] for h in hits)
    if len({h.rule for h in hits}) >= 2:          # independent signals agree -> escalate one level
        level = min(level + 1, len(SEVERITIES) - 1)
    return SEVERITIES[level]


class DetectionEngine:
    def __init__(self, policy: Policy, mode: str | None = None, seed: int = 42) -> None:
        self.policy = policy
        self.mode = mode or policy.detection.mode
        self.state = StreamState(policy)
        self.rules = RuleEngine(policy)
        self.ml = MLDetector(policy.detection.ml, seed=seed)
        self.use_rules = self.mode in ("rules", "hybrid")
        self.use_ml = self.mode in ("ml", "hybrid") and policy.detection.ml.enabled
        self.processed = 0
        self._ml_flags: dict = {}          # source_ip -> SlidingCounter of raw model flags

    def _ml_persistent(self, ev: Event) -> bool:
        """True once the model has flagged this source `persistence` times within the window."""
        c = self._ml_flags.get(ev.source_ip)
        if c is None:
            if len(self._ml_flags) > 10_000:      # bound memory under spoofed-source floods
                horizon = self.policy.detection.window_seconds
                self._ml_flags = {k: v for k, v in self._ml_flags.items() if v.count(ev.timestamp, horizon)}
            c = self._ml_flags[ev.source_ip] = SlidingCounter()
        return c.add(ev.timestamp, self.policy.detection.window_seconds) >= self.policy.detection.ml.persistence

    # -- main entry point ------------------------------------------------
    def process_batch(self, events: Iterable[Event]) -> list:
        events = list(events)
        n = len(events)
        rule_hits: list = []
        feats: list = []

        for ev in events:
            ctx = self.state.observe(ev)
            hits = self.rules.evaluate(ev, ctx)
            if not hits:
                self.state.learn(ev)           # only clean events shape the baseline
            if self.use_ml:
                f = ml_features(ev, ctx)
                feats.append(f)
                if not hits and ctx.baseline_ready:
                    self.ml.add_training(f)
            rule_hits.append(hits)

        scores = self.ml.score(feats) if (self.use_ml and self.ml.ready and n) else None

        out: list = []
        for i, ev in enumerate(events):
            det = Detection(event=ev)
            hits = list(rule_hits[i]) if self.use_rules else []
            if scores is not None:
                det.ml_score = float(scores[i])
                det.ml_flag = det.ml_score < self.ml.threshold
                if det.ml_flag and self._ml_persistent(ev):
                    hits.append(RuleHit(
                        "ML_ANOMALY", "low",           # statistical hint: ranks below explicit rules
                        f"anomaly score {det.ml_score:.3f} below learned threshold {self.ml.threshold:.3f}"))
            if hits:
                det.hits = hits
                det.flagged = True
                det.risk_score = min(100, sum(RULE_WEIGHTS.get(h.rule, 10) for h in {h.rule: h for h in hits}.values()))
                det.severity = _severity(hits)
            out.append(det)

        self.processed += n
        if self.use_ml:
            self.ml.maybe_fit()
        return out

    def process_event(self, ev: Event) -> Detection:
        return self.process_batch([ev])[0]

    # -- helpers ---------------------------------------------------------
    def warm_up(self, events: Iterable[Event], batch: int = 500) -> int:
        """Feed known-clean traffic to build baselines and train the model."""
        buf, total = [], 0
        for ev in events:
            buf.append(ev)
            if len(buf) >= batch:
                self.process_batch(buf)
                total += len(buf)
                buf = []
        if buf:
            self.process_batch(buf)
            total += len(buf)
        if self.use_ml:
            self.ml.maybe_fit(force=True)
        return total

    def info(self) -> dict:
        done, need = self.ml.progress
        return {
            "mode": self.mode,
            "rules_active": self.use_rules,
            "ml_enabled": self.use_ml,
            "ml_ready": self.ml.ready,
            "ml_warmup_done": done,
            "ml_warmup_needed": need,
            "ml_threshold": round(self.ml.threshold, 4) if self.ml.ready else None,
            "events_processed": self.processed,
        }
