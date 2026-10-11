"""Rule-based detector: explicit, explainable checks against the policy.

Each rule maps to a class of serverless risk (OWASP Serverless Top 10 /
Cloud Security Alliance FaaS guidance) and returns a human-readable reason,
which is what makes the system auditable in a viva or a SOC.

    INVOCATION_FLOOD   denial-of-service / denial-of-wallet (resource exhaustion)
    AUTH_BRUTEFORCE    broken authentication, credential stuffing
    UNAUTHORIZED_CALL  business-logic abuse / lateral movement along the call graph
    PAYLOAD_ANOMALY    oversized or abnormal input (injection / exfiltration staging)
    DURATION_ANOMALY   resource abuse (cryptomining, ReDoS-style hangs)
    ERROR_SPIKE        exploitation attempts / probing causing server errors
"""
from __future__ import annotations

from .config import Policy
from .models import Event, RuleHit
from .state import Context

# Weight each rule adds to the 0-100 risk score, and its base severity.
RULE_WEIGHTS = {
    "UNAUTHORIZED_CALL": 45,
    "INVOCATION_FLOOD": 40,
    "AUTH_BRUTEFORCE": 40,
    "PAYLOAD_ANOMALY": 30,
    "DURATION_ANOMALY": 30,
    "ERROR_SPIKE": 20,
    "ML_ANOMALY": 25,
}
RULE_SEVERITY = {
    "UNAUTHORIZED_CALL": "high",
    "INVOCATION_FLOOD": "high",
    "AUTH_BRUTEFORCE": "high",
    "PAYLOAD_ANOMALY": "medium",
    "DURATION_ANOMALY": "medium",
    "ERROR_SPIKE": "low",
    "ML_ANOMALY": "low",
}


class RuleEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.cfg = policy.detection

    def evaluate(self, ev: Event, ctx: Context) -> list:
        cfg = self.cfg
        hits: list = []

        # 1. Flood. Attributed to the abusive *source* so legitimate callers that happen to hit the
        #    same function during an attack are not flagged (a source must contribute >= 20% of a function's
        #    volume to be blamed for it), and a legitimate traffic surge spread
        #    over many clients does not alert. (Known gap: a flood spread thinly over thousands of
        #    sources needs platform-level rate limiting; see docs/ARCHITECTURE.md.)
        if ctx.src_count > cfg.max_invocations_per_source_window:
            hits.append(RuleHit(
                "INVOCATION_FLOOD", "high",
                f"source {ev.source_ip} made {ctx.src_count} calls in {cfg.window_seconds:g}s "
                f"(limit {cfg.max_invocations_per_source_window})"))
        elif (ctx.fn_count > cfg.max_invocations_per_function_window
              and ctx.src_count >= max(10, 0.2 * ctx.fn_count)):
            hits.append(RuleHit(
                "INVOCATION_FLOOD", "high",
                f"{ctx.fn_count} calls to {ev.function_name} in {cfg.window_seconds:g}s "
                f"(limit {cfg.max_invocations_per_function_window}); source {ev.source_ip} "
                f"contributes {ctx.src_count}"))

        # 2. Repeated authentication failures from one source.
        if ctx.auth_fail_src > cfg.max_auth_failures_per_source_window:
            hits.append(RuleHit(
                "AUTH_BRUTEFORCE", "high",
                f"{ctx.auth_fail_src} auth failures from {ev.source_ip} in {cfg.window_seconds:g}s"))

        # 3. Call-graph violation.
        if not ctx.caller_known:
            hits.append(RuleHit(
                "UNAUTHORIZED_CALL", "high",
                f"{ev.caller} is not allowed to call {ev.function_name}"))

        # 4. Payload: hard cap from policy, or statistical outlier vs. this function's baseline.
        cap = self.policy.max_payload(ev.function_name)
        if ev.payload_size_bytes > cap:
            hits.append(RuleHit(
                "PAYLOAD_ANOMALY", "medium",
                f"payload {ev.payload_size_bytes}B exceeds policy cap {cap}B"))
        elif ctx.payload_z > cfg.zscore_threshold:
            hits.append(RuleHit(
                "PAYLOAD_ANOMALY", "medium",
                f"payload {ev.payload_size_bytes}B is {ctx.payload_z:.1f} sigma above this function's norm"))

        # 5. Duration outlier.
        if ctx.duration_z > cfg.zscore_threshold:
            hits.append(RuleHit(
                "DURATION_ANOMALY", "medium",
                f"duration {ev.duration_ms:.0f}ms is {ctx.duration_z:.1f} sigma above this function's norm"))

        # 6. Server-error burst.
        if ctx.err_fn > cfg.max_server_errors_per_function_window:
            hits.append(RuleHit(
                "ERROR_SPIKE", "low",
                f"{ctx.err_fn} server errors from {ev.function_name} in {cfg.window_seconds:g}s"))
        return hits
