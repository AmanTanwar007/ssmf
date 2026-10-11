"""Core data models shared by the engine, storage, alerting and API layers.

Plain dataclasses (with __slots__) are used inside the hot detection path for
speed; the API layer validates untrusted input with pydantic and converts to
these types (see api.py).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(slots=True)
class Event:
    """One function invocation, as reported by the SDK or a log collector."""
    invocation_id: str
    timestamp: float                 # epoch seconds
    function_name: str
    caller: str = "external"         # "external" or the name of the calling function
    source_ip: str = "unknown"
    status_code: int = 200
    duration_ms: float = 0.0
    payload_size_bytes: int = 0
    label: Optional[str] = None      # ground truth; only set by the simulator/evaluation


@dataclass(slots=True)
class RuleHit:
    rule: str
    severity: str
    message: str


@dataclass(slots=True)
class Detection:
    """Result of running one event through the engine."""
    event: Event
    hits: list = field(default_factory=list)      # list[RuleHit]
    ml_score: Optional[float] = None              # IsolationForest decision value (lower = stranger)
    ml_flag: bool = False
    flagged: bool = False
    risk_score: int = 0
    severity: Optional[str] = None

    @property
    def rule_names(self) -> list:
        return [h.rule for h in self.hits]


@dataclass(slots=True)
class Alert:
    alert_id: str
    timestamp: float
    function_name: str
    rule: str                  # primary rule
    rules: list                # all rules that fired
    severity: str
    risk_score: int
    source_ip: str
    caller: str
    message: str
    invocation_id: str
    suppressed: int = 0        # similar alerts folded into this one by the cooldown

    def to_dict(self) -> dict:
        return asdict(self)
