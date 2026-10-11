"""Alert generation: de-duplication plus pluggable notification sinks.

A flood of 500 malicious invocations should produce one actionable alert,
not 500. Identical (function, rule, source) detections inside the cooldown are
folded into the open alert, whose `suppressed` counter then shows how many
similar events it represents. Each distinct rule gets its own alert, so a
brute-force attack is never hidden behind an earlier flood alert from the
same source.
Sinks never raise: a dead webhook must not break detection.
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.request
import uuid

from .config import AlertSettings
from .models import Alert, Detection

log = logging.getLogger("ssmf.alerts")


class LogSink:
    def send(self, alert: Alert) -> None:
        log.warning("[%s] %s on %s from %s: %s (risk %d)", alert.severity.upper(), alert.rule,
                    alert.function_name, alert.source_ip, alert.message, alert.risk_score)


class JsonlSink:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()

    def send(self, alert: Alert) -> None:
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.to_dict()) + "\n")


class WebhookSink:
    """Slack-compatible incoming-webhook payload, posted from a background thread."""
    def __init__(self, url: str) -> None:
        self.url = url

    def send(self, alert: Alert) -> None:
        text = (f":rotating_light: *{alert.severity.upper()}* {alert.rule} on `{alert.function_name}` "
                f"from `{alert.source_ip}` - {alert.message}")
        body = json.dumps({"text": text}).encode()

        def _post() -> None:
            try:
                req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=3).read()
            except Exception as exc:      # noqa: BLE001 - alert delivery must never crash the pipeline
                log.error("webhook delivery failed: %s", exc)

        threading.Thread(target=_post, daemon=True).start()


class AlertManager:
    def __init__(self, settings: AlertSettings, sinks: list | None = None) -> None:
        self.cooldown = settings.cooldown_seconds
        self.sinks = sinks if sinks is not None else self._default_sinks(settings)
        self._last: dict = {}            # key -> (last_ts, Alert) of the most recent alert
        self._dirty: dict = {}           # alert_id -> Alert whose suppressed count changed
        self.suppressed_total = 0

    @staticmethod
    def _default_sinks(settings: AlertSettings) -> list:
        sinks: list = [LogSink()]
        if settings.jsonl_path:
            sinks.append(JsonlSink(settings.jsonl_path))
        if settings.webhook_url:
            sinks.append(WebhookSink(settings.webhook_url))
        return sinks

    def process(self, det: Detection) -> list:
        """Turn a flagged detection into Alerts - one per distinct rule - skipping any that fold into
        an already-open alert for the same (function, rule, source). ML_ANOMALY only becomes its own
        alert when no explicit rule fired; otherwise it is corroboration inside the rule alert."""
        if not det.flagged:
            return []
        ev = det.event
        hits = [h for h in det.hits if h.rule != "ML_ANOMALY"] or list(det.hits)
        created: list = []
        for hit in hits:
            key = (ev.function_name, hit.rule, ev.source_ip)
            entry = self._last.get(key)
            if entry and ev.timestamp - entry[0] < self.cooldown:
                entry[1].suppressed += 1                 # fold into the alert that is already open
                self._dirty[entry[1].alert_id] = entry[1]
                self.suppressed_total += 1
                continue

            alert = Alert(
                alert_id=uuid.uuid4().hex[:12], timestamp=ev.timestamp, function_name=ev.function_name,
                rule=hit.rule, rules=det.rule_names, severity=det.severity or "low",
                risk_score=det.risk_score, source_ip=ev.source_ip, caller=ev.caller,
                message=hit.message, invocation_id=ev.invocation_id)
            self._last[key] = (ev.timestamp, alert)
            if len(self._last) > 10_000:                       # bound memory
                for k in list(self._last)[:5_000]:
                    del self._last[k]
            for sink in self.sinks:
                try:
                    sink.send(alert)
                except Exception as exc:          # noqa: BLE001
                    log.error("alert sink %s failed: %s", type(sink).__name__, exc)
            created.append(alert)
        return created

    def drain_updated(self) -> list:
        """Alerts whose `suppressed` counter grew since the last call (to be re-persisted)."""
        out = list(self._dirty.values())
        self._dirty.clear()
        return out
