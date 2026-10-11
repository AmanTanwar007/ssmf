"""HTTP API for the SSMF monitor.

    POST /api/v1/events          ingest one event or a batch   (X-SSMF-Key if configured)
    GET  /api/v1/alerts          recent alerts
    GET  /api/v1/events          recent events (?flagged_only=true)
    GET  /api/v1/stats           aggregates + time series + engine status (dashboard feed)
    GET  /api/v1/policy          the active policy (call graph + limits)
    POST /api/v1/admin/reset     wipe data and re-learn baselines (X-SSMF-Key)
    GET  /metrics                Prometheus exposition format
    GET  /health                 liveness
    GET  /                       live dashboard

Run:  uvicorn ssmf.api:create_app --factory --host 0.0.0.0 --port 8000

Security notes
  * All identifiers are pattern-validated, which blocks log/metric/HTML injection
    through function names, callers or IPs.
  * Ingest is size-limited (1 MB body, 1000 events per request).
  * The API key is compared in constant time.
"""
from __future__ import annotations

import hmac
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .config import load_policy
from .models import Event
from .service import MonitorService
from .storage import Store

STATIC_DIR = Path(__file__).with_name("static")
MAX_BODY_BYTES = 1_000_000
MAX_BATCH = 1000
_IDENT = r"^[A-Za-z0-9_.:\-]{1,80}$"


class EventIn(BaseModel):
    invocation_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12], pattern=_IDENT)
    timestamp: Optional[float] = Field(default=None, ge=0)
    function_name: str = Field(pattern=_IDENT)
    caller: str = Field(default="external", pattern=_IDENT)
    source_ip: str = Field(default="unknown", pattern=_IDENT)
    status_code: int = Field(default=200, ge=100, le=599)
    duration_ms: float = Field(default=0.0, ge=0, le=3_600_000)
    payload_size_bytes: int = Field(default=0, ge=0, le=2_000_000_000)

    def to_event(self) -> Event:
        return Event(
            invocation_id=self.invocation_id,
            timestamp=self.timestamp if self.timestamp is not None else time.time(),
            function_name=self.function_name, caller=self.caller, source_ip=self.source_ip,
            status_code=self.status_code, duration_ms=self.duration_ms,
            payload_size_bytes=self.payload_size_bytes,
        )


def create_app(policy_path: str | None = None, db_path: str | None = None,
               mode: str | None = None, api_key: str | None = None) -> FastAPI:
    policy = load_policy(policy_path, mode=mode)
    store = Store(db_path or os.environ.get("SSMF_DB", "ssmf.db"))
    service = MonitorService(policy, store)
    key = api_key if api_key is not None else os.environ.get("SSMF_API_KEY", "")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        store.close()

    app = FastAPI(title="SSMF - Serverless Security Monitoring Framework", version="1.0.0",
                  lifespan=lifespan)
    app.state.service = service

    def require_key(x_ssmf_key: str = Header(default="")) -> None:
        if key and not hmac.compare_digest(x_ssmf_key.encode(), key.encode()):
            raise HTTPException(status_code=401, detail="invalid or missing X-SSMF-Key")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'")
        return resp

    @app.post("/api/v1/events", dependencies=[Depends(require_key)])
    def ingest(events: List[EventIn]):
        if len(events) > MAX_BATCH:
            raise HTTPException(status_code=413, detail=f"max {MAX_BATCH} events per request")
        result = service.ingest([e.to_event() for e in events])
        return {"accepted": result["accepted"], "new_alerts": len(result["alerts"])}

    @app.get("/api/v1/alerts")
    def alerts(limit: int = Query(50, ge=1, le=500), severity: Optional[str] = None):
        if severity and severity not in ("low", "medium", "high", "critical"):
            raise HTTPException(status_code=422, detail="severity must be low|medium|high|critical")
        return store.recent_alerts(limit, severity)

    @app.get("/api/v1/events")
    def events_(limit: int = Query(100, ge=1, le=1000), flagged_only: bool = False):
        return store.recent_events(limit, flagged_only)

    @app.get("/api/v1/stats")
    def stats():
        return service.snapshot()

    @app.get("/api/v1/policy")
    def policy_view():
        return {
            "functions": {n: {"allowed_callers": sorted(f.allowed_callers),
                              "max_payload_bytes": f.max_payload_bytes}
                          for n, f in policy.functions.items()},
            "detection": {"mode": service.engine.mode, "window_seconds": policy.detection.window_seconds,
                          "zscore_threshold": policy.detection.zscore_threshold},
        }

    @app.post("/api/v1/admin/reset", dependencies=[Depends(require_key)])
    def reset():
        service.reset()
        return {"status": "reset"}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        return service.prometheus_metrics()

    @app.get("/health")
    def health():
        return {"status": "ok", "ml_ready": service.engine.ml.ready}

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC_DIR / "dashboard.html")

    return app
