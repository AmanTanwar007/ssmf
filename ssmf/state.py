"""Streaming state shared by the rule engine and the ML detector.

Everything here is O(1) amortised per event:
  * sliding-window counters (deques that are trimmed as time advances)
  * exponentially-weighted running mean/variance of log(payload) and
    log(duration) per function (the per-function "normal" baseline)

Detection uses the *event timestamps*, not the wall clock, so the same code
works for live traffic and for accelerated replay in the evaluation tool.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass

from .config import DetectionSettings, Policy
from .models import Event

_MAX_TRACKED_KEYS = 20_000     # hard cap on per-source / per-function windows (memory safety)


class SlidingCounter:
    """Counts how many timestamps fall inside the trailing window."""
    __slots__ = ("q",)

    def __init__(self) -> None:
        self.q: deque = deque()

    def add(self, t: float, horizon: float) -> int:
        self.q.append(t)
        cutoff = t - horizon
        q = self.q
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def count(self, now: float, horizon: float) -> int:
        cutoff = now - horizon
        q = self.q
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)


class RunningStats:
    """Exponentially-weighted mean/variance (Welford-style).

    Behaves like an ordinary running mean/variance for the first `window`
    samples and then forgets old data, so the baseline follows slow drift.
    """
    __slots__ = ("n", "mean", "var", "window")

    def __init__(self, window: int) -> None:
        self.n = 0
        self.mean = 0.0
        self.var = 0.0
        self.window = window

    def update(self, x: float) -> None:
        self.n += 1
        alpha = 1.0 / min(self.n, self.window)
        diff = x - self.mean
        incr = alpha * diff
        self.mean += incr
        self.var = (1.0 - alpha) * (self.var + diff * incr)

    @property
    def std(self) -> float:
        return math.sqrt(self.var) if self.var > 0 else 0.0


@dataclass(slots=True)
class Context:
    """Per-event snapshot of what the stream looked like when it arrived."""
    fn_count: int            # invocations of this function in the window (incl. this one)
    src_count: int           # invocations from this source IP in the window
    auth_fail_src: int       # 401/403 responses attributed to this source in the window
    err_fn: int              # 5xx responses of this function in the window
    payload_z: float
    duration_z: float
    caller_known: bool
    baseline_ready: bool     # enough history for the z-scores to be meaningful


class StreamState:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.cfg: DetectionSettings = policy.detection
        self.fn_windows: dict = {}
        self.src_windows: dict = {}
        self.auth_windows: dict = {}
        self.err_windows: dict = {}
        self.payload_stats: dict = {}
        self.duration_stats: dict = {}
        self._seen = 0

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _counter(store: dict, key: str) -> SlidingCounter:
        c = store.get(key)
        if c is None:
            c = store[key] = SlidingCounter()
        return c

    def _stats(self, store: dict, key: str) -> RunningStats:
        s = store.get(key)
        if s is None:
            s = store[key] = RunningStats(self.cfg.baseline_window)
        return s

    def _z(self, stats: RunningStats, x: float) -> float:
        if stats.n < self.cfg.min_samples:
            return 0.0
        std = max(stats.std, self.cfg.min_log_std)
        return (x - stats.mean) / std

    def _gc(self, now: float) -> None:
        """Drop empty windows so a flood of spoofed source IPs cannot grow memory without bound."""
        horizon = self.cfg.window_seconds
        for store in (self.src_windows, self.auth_windows):
            if len(store) > _MAX_TRACKED_KEYS // 2:
                for k in [k for k, c in store.items() if c.count(now, horizon) == 0]:
                    del store[k]
                if len(store) > _MAX_TRACKED_KEYS:      # still too big: drop oldest-inserted
                    for k in list(store)[: len(store) - _MAX_TRACKED_KEYS]:
                        del store[k]

    # -- public API ------------------------------------------------------
    def observe(self, ev: Event) -> Context:
        """Register the event in all windows and return its context."""
        h = self.cfg.window_seconds
        t = ev.timestamp
        fn_count = self._counter(self.fn_windows, ev.function_name).add(t, h)
        src_count = self._counter(self.src_windows, ev.source_ip).add(t, h)

        if ev.status_code in (401, 403):
            auth_fail_src = self._counter(self.auth_windows, ev.source_ip).add(t, h)
        else:
            auth_fail_src = self._counter(self.auth_windows, ev.source_ip).count(t, h) \
                if ev.source_ip in self.auth_windows else 0

        if ev.status_code >= 500:
            err_fn = self._counter(self.err_windows, ev.function_name).add(t, h)
        else:
            err_fn = self._counter(self.err_windows, ev.function_name).count(t, h) \
                if ev.function_name in self.err_windows else 0

        ps = self._stats(self.payload_stats, ev.function_name)
        ds = self._stats(self.duration_stats, ev.function_name)
        ready = ps.n >= self.cfg.min_samples and ds.n >= self.cfg.min_samples
        ctx = Context(
            fn_count=fn_count,
            src_count=src_count,
            auth_fail_src=auth_fail_src,
            err_fn=err_fn,
            payload_z=self._z(ps, math.log1p(max(ev.payload_size_bytes, 0))),
            duration_z=self._z(ds, math.log1p(max(ev.duration_ms, 0.0))),
            caller_known=ev.caller in self.policy.allowed_callers(ev.function_name),
            baseline_ready=ready,
        )

        self._seen += 1
        if self._seen % 5000 == 0:
            self._gc(t)
        return ctx

    def learn(self, ev: Event) -> None:
        """Fold a *clean* event into the per-function baseline.

        Callers must not pass events that were flagged: otherwise an attacker
        could slowly drag the baseline towards the attack ("baseline poisoning").
        """
        self._stats(self.payload_stats, ev.function_name).update(math.log1p(max(ev.payload_size_bytes, 0)))
        self._stats(self.duration_stats, ev.function_name).update(math.log1p(max(ev.duration_ms, 0.0)))
