"""MonitorService: ingest -> detect -> persist -> alert, with runtime metrics."""
from __future__ import annotations

import threading
import time
from collections import defaultdict

from .alerting import AlertManager
from .config import Policy
from .engine import DetectionEngine
from .storage import Store


class MonitorService:
    def __init__(self, policy: Policy, store: Store, alert_manager: AlertManager | None = None,
                 mode: str | None = None) -> None:
        self.policy = policy
        self.store = store
        self.alerts = alert_manager or AlertManager(policy.alerting)
        self.engine = DetectionEngine(policy, mode=mode)
        self._lock = threading.Lock()                 # the engine's state is not thread-safe
        self.started_at = time.time()
        # metrics
        self.events_by_function: dict = defaultdict(int)
        self.alerts_by_rule_sev: dict = defaultdict(int)
        self.latency_sum = 0.0
        self.latency_count = 0
        self.latency_max = 0.0

    def ingest(self, events: list) -> dict:
        """Process a batch of Event objects. Returns {"accepted": n, "alerts": [Alert,...]}."""
        if not events:
            return {"accepted": 0, "alerts": []}
        t0 = time.perf_counter()
        with self._lock:
            dets = self.engine.process_batch(events)
            new_alerts = [a for d in dets for a in self.alerts.process(d)]
            updated = self.alerts.drain_updated()
        elapsed = time.perf_counter() - t0

        self.store.insert_detections(dets)
        for a in new_alerts:
            self.store.insert_alert(a)
        for a in updated:                              # persist grown "suppressed" counters
            self.store.insert_alert(a)

        per_event = elapsed / len(events)
        self.latency_sum += elapsed
        self.latency_count += len(events)
        self.latency_max = max(self.latency_max, per_event)
        for e in events:
            self.events_by_function[e.function_name] += 1
        for a in new_alerts:
            self.alerts_by_rule_sev[(a.rule, a.severity)] += 1
        return {"accepted": len(events), "alerts": new_alerts}

    def snapshot(self) -> dict:
        data = self.store.stats()
        data["engine"] = self.engine.info()
        data["uptime_seconds"] = round(time.time() - self.started_at, 1)
        data["suppressed_duplicates"] = self.alerts.suppressed_total
        data["avg_detection_latency_ms"] = round(
            1000 * self.latency_sum / self.latency_count, 4) if self.latency_count else 0.0
        return data

    def reset(self) -> None:
        with self._lock:
            self.engine = DetectionEngine(self.policy, mode=self.engine.mode)
            self.alerts = AlertManager(self.policy.alerting, sinks=self.alerts.sinks)
        self.store.reset()
        self.events_by_function.clear()
        self.alerts_by_rule_sev.clear()
        self.latency_sum = self.latency_max = 0.0
        self.latency_count = 0

    def prometheus_metrics(self) -> str:
        def esc(v: str) -> str:
            return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        lines = [
            "# HELP ssmf_events_total Function invocations processed.",
            "# TYPE ssmf_events_total counter",
        ]
        for fn, n in sorted(self.events_by_function.items()):
            lines.append(f'ssmf_events_total{{function="{esc(fn)}"}} {n}')
        lines += ["# HELP ssmf_alerts_total Alerts raised.", "# TYPE ssmf_alerts_total counter"]
        for (rule, sev), n in sorted(self.alerts_by_rule_sev.items()):
            lines.append(f'ssmf_alerts_total{{rule="{esc(rule)}",severity="{esc(sev)}"}} {n}')
        info = self.engine.info()
        lines += [
            "# HELP ssmf_alerts_suppressed_total Duplicate detections folded into open alerts.",
            "# TYPE ssmf_alerts_suppressed_total counter",
            f"ssmf_alerts_suppressed_total {self.alerts.suppressed_total}",
            "# HELP ssmf_detection_seconds_sum Total time spent in detection.",
            "# TYPE ssmf_detection_seconds_sum counter",
            f"ssmf_detection_seconds_sum {self.latency_sum:.6f}",
            "# TYPE ssmf_detection_events_count counter",
            f"ssmf_detection_events_count {self.latency_count}",
            "# HELP ssmf_ml_ready 1 once the ML model has finished its learning period.",
            "# TYPE ssmf_ml_ready gauge",
            f"ssmf_ml_ready {1 if info['ml_ready'] else 0}",
        ]
        return "\n".join(lines) + "\n"
