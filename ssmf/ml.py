"""Unsupervised ML detector.

Unsupervised because a fresh deployment has no labelled attacks: the model
learns "normal" from the first `warmup_events` clean events, then scores
every later event. Part of that warm-up is held out to calibrate the alarm
threshold, so the false-positive rate is set on data the model has not seen.

Features (all per-event and attributable to the event's own source):
    payload_z, duration_z   z-scores against the function's own baseline, so one
                            global model works for functions whose raw payload
                            sizes differ by orders of magnitude
    log_src_count           calls from this source in the window
    auth_fail_src           auth failures from this source in the window
    is_error                4xx/5xx response
Function-wide volume is deliberately NOT a feature: it would flag legitimate
callers as "anomalous" whenever someone else floods the same function.

Algorithms (selectable via policy `ml.algorithm`; compared in tools/evaluate.py)
    lof          Local Outlier Factor (novelty mode)   <- default
    iforest      Isolation Forest
    mahalanobis  Mahalanobis distance
Measured finding (docs/EVALUATION.md): Isolation Forest scores far-out-of-range
points only marginally lower than normal ones, so it misses large anomalies;
distance-based LOF / Mahalanobis do not have that weakness.

Policy violations (call graph) are intentionally left to the rules: a feature
that never varies in training cannot be learned from.
"""
from __future__ import annotations

import math

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from .config import MLSettings
from .models import Event
from .state import Context

FEATURE_NAMES = ["payload_z", "duration_z", "log_src_count", "auth_fail_src", "is_error"]


def features(ev: Event, ctx: Context) -> list:
    return [
        max(-10.0, min(20.0, ctx.payload_z)),
        max(-10.0, min(20.0, ctx.duration_z)),
        math.log1p(ctx.src_count),
        float(min(ctx.auth_fail_src, 50)),
        1.0 if ev.status_code >= 400 else 0.0,
    ]


# Each builder takes the fitting matrix and returns scorer(X) -> array, HIGHER = MORE NORMAL.
def _build_lof(X, s: MLSettings, seed: int):
    model = LocalOutlierFactor(n_neighbors=max(5, min(s.n_neighbors, len(X) - 1)), novelty=True).fit(X)
    return model.decision_function


def _build_iforest(X, s: MLSettings, seed: int):
    model = IsolationForest(n_estimators=s.n_estimators, max_samples=min(256, len(X)),
                            random_state=seed).fit(X)
    return model.decision_function


def _build_mahalanobis(X, s: MLSettings, seed: int):
    mu, sd = X.mean(axis=0), X.std(axis=0) + 1e-6
    Z = (X - mu) / sd
    inv = np.linalg.pinv(np.cov(Z.T) + np.eye(Z.shape[1]) * 1e-3)

    def scorer(Y):
        D = (Y - mu) / sd
        return -np.sqrt(np.maximum(np.einsum("ij,jk,ik->i", D, inv, D), 0.0))
    return scorer


_BUILDERS = {"lof": _build_lof, "iforest": _build_iforest, "mahalanobis": _build_mahalanobis}


class MLDetector:
    def __init__(self, settings: MLSettings, seed: int = 42) -> None:
        self.settings = settings
        self.seed = seed
        self._scorer = None
        self.threshold: float = 0.0
        self._buffer: list = []

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    @property
    def ready(self) -> bool:
        return self._scorer is not None

    @property
    def progress(self) -> tuple:
        return (min(len(self._buffer), self.settings.warmup_events), self.settings.warmup_events)

    def add_training(self, feats: list) -> None:
        if self._scorer is None and len(self._buffer) < self.settings.warmup_events:
            self._buffer.append(feats)

    def maybe_fit(self, force: bool = False) -> bool:
        if self._scorer is not None or not self.enabled:
            return False
        if len(self._buffer) < self.settings.warmup_events and not (force and len(self._buffer) >= 100):
            return False
        X = np.asarray(self._buffer, dtype=float)
        # Interleaved split (not chronological) so calibration data covers the whole warm-up period.
        every = max(2, round(1.0 / self.settings.calibration_fraction))
        is_cal = (np.arange(len(X)) % every) == 0
        X_fit, X_cal = X[~is_cal], X[is_cal]
        scorer = _BUILDERS[self.settings.algorithm](X_fit, self.settings, self.seed)
        self.threshold = float(np.quantile(scorer(X_cal), self.settings.false_positive_target))
        self._scorer = scorer
        self._buffer = []
        return True

    def score(self, feature_rows: list):
        """Vectorised scoring of a micro-batch (higher = more normal)."""
        return self._scorer(np.asarray(feature_rows, dtype=float))
