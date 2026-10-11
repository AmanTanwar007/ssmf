"""ssmf_sdk - drop-in instrumentation for serverless functions (zero dependencies).

    from ssmf_sdk import monitored

    @monitored("payment-process")
    def handle(event, context):
        ...

The decorator measures every invocation (duration, payload size, status,
caller, source IP) and reports it to the SSMF monitor from a background
thread, so the function's latency is not affected by the monitor's.
Monitoring failures never break the function.

Configuration (environment variables)
    SSMF_MONITOR_URL     e.g. http://ssmf-monitor:8000          (default http://127.0.0.1:8000)
    SSMF_API_KEY         ingest key (or mount an OpenFaaS secret named "ssmf-api-key")
    SSMF_CALLER_SECRET   shared secret used to sign/verify the calling-function identity
                         (or an OpenFaaS secret named "ssmf-caller-secret")
    SSMF_SYNC=1          send each event inline (for platforms that freeze the container
                         right after the response, where a background thread may never run)
    SSMF_STDOUT_LOG=1    also print each event as an `SSMF_EVENT {json}` log line

Caller identity: a bare "X-Caller-Function" header can be forged by any client.
When SSMF_CALLER_SECRET is set, callers must also send a time-stamped HMAC
(see `caller_headers`); a forged or stale identity is recorded as
"spoofed:<claimed-name>", which the monitor flags as UNAUTHORIZED_CALL.
"""
from __future__ import annotations

import atexit
import functools
import hashlib
import hmac
import json
import os
import queue
import re
import sys
import threading
import time
import urllib.request
import uuid

__all__ = ["monitored", "Reporter", "caller_headers", "get_reporter"]

_SAFE = re.compile(r"[^A-Za-z0-9_.:\-]")
_SKEW_SECONDS = 300


def _clean(value, default="unknown", limit=64) -> str:
    value = _SAFE.sub("_", str(value or ""))[:limit]
    return value or default


def _secret(env_name: str, file_name: str):
    val = os.environ.get(env_name)
    if val:
        return val
    try:
        with open(f"/var/openfaas/secrets/{file_name}", "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


# ---------------------------------------------------------------- reporting
class Reporter:
    """Batches events and ships them to the monitor on a daemon thread."""

    def __init__(self, url=None, api_key=None, sink=None, batch_size=50, flush_interval=0.5,
                 max_queue=10_000, sync=None, stdout_log=None):
        self.url = (url or os.environ.get("SSMF_MONITOR_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.api_key = api_key if api_key is not None else (_secret("SSMF_API_KEY", "ssmf-api-key") or "")
        self.sink = sink                       # optional callable(list[dict]) - used by tests/benchmarks
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.sync = os.environ.get("SSMF_SYNC") == "1" if sync is None else sync
        self.stdout_log = os.environ.get("SSMF_STDOUT_LOG") == "1" if stdout_log is None else stdout_log
        self.dropped = 0
        self.failures = 0
        self._last_warn = 0.0
        self._q: queue.Queue = queue.Queue(maxsize=max_queue)
        self._thread = None
        if not self.sync:
            self._thread = threading.Thread(target=self._run, name="ssmf-reporter", daemon=True)
            self._thread.start()

    def emit(self, event: dict) -> None:
        if self.stdout_log:
            print("SSMF_EVENT " + json.dumps(event), flush=True)
        if self.sync:
            self._send([event])
            return
        try:
            self._q.put_nowait(event)
        except queue.Full:
            self.dropped += 1                   # shed load rather than block the function

    def flush(self, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while self._q.unfinished_tasks and time.time() < deadline:
            time.sleep(0.01)
        return self._q.unfinished_tasks == 0

    def _run(self) -> None:
        while True:
            batch = [self._q.get()]
            deadline = time.time() + self.flush_interval
            while len(batch) < self.batch_size and time.time() < deadline:
                try:
                    batch.append(self._q.get(timeout=max(0.0, deadline - time.time())))
                except queue.Empty:
                    break
            try:
                self._send(batch)
            finally:
                for _ in batch:
                    self._q.task_done()

    def _send(self, batch: list) -> None:
        try:
            if self.sink is not None:
                self.sink(batch)
                return
            req = urllib.request.Request(
                self.url + "/api/v1/events", data=json.dumps(batch).encode(),
                headers={"Content-Type": "application/json", "X-SSMF-Key": self.api_key})
            urllib.request.urlopen(req, timeout=2).read()
        except Exception as exc:                 # noqa: BLE001 - never propagate into the function
            self.failures += 1
            if time.time() - self._last_warn > 30:
                self._last_warn = time.time()
                print(f"[ssmf_sdk] could not reach monitor ({exc}); events dropped", file=sys.stderr)


_default_reporter = None
_reporter_lock = threading.Lock()


def get_reporter() -> Reporter:
    global _default_reporter
    with _reporter_lock:
        if _default_reporter is None:
            _default_reporter = Reporter()
            atexit.register(_default_reporter.flush, 2.0)
        return _default_reporter


# ---------------------------------------------------------- caller identity
def caller_headers(caller_name: str) -> dict:
    """Headers a function must attach when calling another function."""
    headers = {"X-Caller-Function": caller_name}
    secret = _secret("SSMF_CALLER_SECRET", "ssmf-caller-secret")
    if secret:
        ts = str(int(time.time()))
        sig = hmac.new(secret.encode(), f"{caller_name}|{ts}".encode(), hashlib.sha256).hexdigest()
        headers["X-Caller-Ts"] = ts
        headers["X-Caller-Sig"] = sig
    return headers


def _resolve_caller(h: dict) -> str:
    claimed = h.get("x-caller-function")
    if not claimed:
        return "external"
    secret = _secret("SSMF_CALLER_SECRET", "ssmf-caller-secret")
    if not secret:
        return _clean(claimed, "external", 80)          # unsigned mode: trust (weaker)
    ts, sig = h.get("x-caller-ts", ""), h.get("x-caller-sig", "")
    try:
        fresh = abs(time.time() - int(ts)) <= _SKEW_SECONDS
    except ValueError:
        fresh = False
    expected = hmac.new(secret.encode(), f"{claimed}|{ts}".encode(), hashlib.sha256).hexdigest()
    if fresh and hmac.compare_digest(expected, sig):
        return _clean(claimed, "external", 80)
    return "spoofed:" + _clean(claimed, "unknown", 60)


# ---------------------------------------------------------------- decorator
def _status_of(result) -> int:
    if isinstance(result, dict):
        code = result.get("statusCode", result.get("status_code", 200))
    else:
        code = getattr(result, "status_code", 200)
    try:
        return int(code)
    except (TypeError, ValueError):
        return 200


def _body_len(event) -> int:
    body = getattr(event, "body", event if isinstance(event, (str, bytes, bytearray)) else b"")
    if isinstance(body, str):
        return len(body.encode("utf-8", "ignore"))
    try:
        return len(body or b"")
    except TypeError:
        return 0


def _headers(event) -> dict:
    raw = getattr(event, "headers", None) or {}
    try:
        return {str(k).lower(): v for k, v in raw.items()}
    except AttributeError:
        return {}


def monitored(function_name: str, reporter: Reporter | None = None):
    """Decorator: report every invocation of the wrapped handler to SSMF."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            event = args[0] if args else None
            started_wall = time.time()
            t0 = time.perf_counter()
            status = 200
            try:
                result = fn(*args, **kwargs)
                status = _status_of(result)
                return result
            except Exception:
                status = 500
                raise
            finally:
                duration_ms = (time.perf_counter() - t0) * 1000.0
                try:
                    h = _headers(event)
                    fwd = (h.get("x-forwarded-for") or h.get("x-real-ip") or "unknown").split(",")[0].strip()
                    (reporter or get_reporter()).emit({
                        "invocation_id": _clean(h.get("x-call-id") or uuid.uuid4().hex[:12], "n/a", 80),
                        "timestamp": started_wall,
                        "function_name": function_name,
                        "caller": _resolve_caller(h),
                        "source_ip": _clean(fwd),
                        "status_code": status,
                        "duration_ms": round(duration_ms, 3),
                        "payload_size_bytes": _body_len(event),
                    })
                except Exception:               # noqa: BLE001 - monitoring must never break the function
                    pass
        return wrapper
    return deco
