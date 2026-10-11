"""Policy loading and validation.

The policy is a YAML file (see default_policy.yaml). Environment variables
override a few deployment-specific settings so the same image can run
anywhere:

    SSMF_POLICY     path to a policy YAML (default: the bundled one)
    SSMF_MODE       rules | ml | hybrid
    SSMF_DB         path of the SQLite database (default: ssmf.db)
    SSMF_API_KEY    if set, ingest/admin endpoints require header X-SSMF-Key
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_POLICY_PATH = Path(__file__).with_name("default_policy.yaml")
VALID_MODES = ("rules", "ml", "hybrid")


class PolicyError(ValueError):
    pass


VALID_ALGORITHMS = ("lof", "iforest", "mahalanobis")


@dataclass
class MLSettings:
    enabled: bool = True
    algorithm: str = "lof"              # lof | iforest | mahalanobis
    warmup_events: int = 800            # clean events collected before the model is trained
    n_neighbors: int = 50               # LOF neighbourhood size
    n_estimators: int = 100             # Isolation Forest trees
    false_positive_target: float = 0.01 # share of held-out clean data allowed below the threshold
    calibration_fraction: float = 0.3   # part of the warm-up held out to set that threshold
    persistence: int = 2                # model flags from one source within the window before ML alerts


@dataclass
class DetectionSettings:
    mode: str = "hybrid"
    window_seconds: float = 10.0
    max_invocations_per_function_window: int = 120
    max_invocations_per_source_window: int = 40
    max_auth_failures_per_source_window: int = 5
    max_server_errors_per_function_window: int = 10
    zscore_threshold: float = 4.0
    min_samples: int = 30
    min_log_std: float = 0.1
    baseline_window: int = 2000
    ml: MLSettings = field(default_factory=MLSettings)


@dataclass
class AlertSettings:
    cooldown_seconds: float = 30.0
    jsonl_path: str = ""
    webhook_url: str = ""


@dataclass
class FunctionPolicy:
    allowed_callers: frozenset
    max_payload_bytes: int = 1_000_000


@dataclass
class Policy:
    functions: dict            # name -> FunctionPolicy
    detection: DetectionSettings
    alerting: AlertSettings

    def allowed_callers(self, function_name: str) -> frozenset:
        fp = self.functions.get(function_name)
        return fp.allowed_callers if fp else frozenset({"external"})

    def max_payload(self, function_name: str) -> int:
        fp = self.functions.get(function_name)
        return fp.max_payload_bytes if fp else 1_000_000


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyError(msg)


def parse_policy(raw: dict) -> Policy:
    _require(isinstance(raw, dict), "policy must be a mapping")
    funcs_raw = raw.get("functions") or {}
    _require(isinstance(funcs_raw, dict) and funcs_raw, "policy.functions must list at least one function")

    functions = {}
    for name, spec in funcs_raw.items():
        spec = spec or {}
        callers = spec.get("allowed_callers", ["external"])
        _require(isinstance(callers, list) and callers, f"{name}: allowed_callers must be a non-empty list")
        functions[name] = FunctionPolicy(
            allowed_callers=frozenset(str(c) for c in callers),
            max_payload_bytes=int(spec.get("max_payload_bytes", 1_000_000)),
        )

    d = dict(raw.get("detection") or {})
    ml = MLSettings(**(d.pop("ml", None) or {}))
    detection = DetectionSettings(ml=ml, **d)
    _require(detection.mode in VALID_MODES, f"detection.mode must be one of {VALID_MODES}")
    _require(detection.window_seconds > 0, "detection.window_seconds must be > 0")
    _require(detection.zscore_threshold > 0, "detection.zscore_threshold must be > 0")
    _require(0 < ml.false_positive_target < 0.5, "ml.false_positive_target must be in (0, 0.5)")
    _require(ml.algorithm in VALID_ALGORITHMS, f"ml.algorithm must be one of {VALID_ALGORITHMS}")
    _require(0.1 <= ml.calibration_fraction <= 0.5, "ml.calibration_fraction must be in [0.1, 0.5]")
    _require(ml.warmup_events >= 100, "ml.warmup_events must be >= 100")
    _require(ml.persistence >= 1, "ml.persistence must be >= 1")

    alerting = AlertSettings(**(raw.get("alerting") or {}))
    return Policy(functions=functions, detection=detection, alerting=alerting)


def load_policy(path: str | os.PathLike | None = None, mode: str | None = None) -> Policy:
    path = path or os.environ.get("SSMF_POLICY") or DEFAULT_POLICY_PATH
    with open(path, "r", encoding="utf-8") as fh:
        policy = parse_policy(yaml.safe_load(fh))     # safe_load: never execute YAML tags
    override = mode or os.environ.get("SSMF_MODE")
    if override:
        _require(override in VALID_MODES, f"mode must be one of {VALID_MODES}")
        policy.detection.mode = override
    return policy
