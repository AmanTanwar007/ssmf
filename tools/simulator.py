"""Labelled synthetic traffic for evaluating the detectors.

Normal traffic follows per-function lognormal payload/duration profiles with
a Poisson arrival process. Attack bursts are injected on top of the normal
background and every attack event carries a ground-truth label
"<attack_type>#<burst_id>" (normal events are labelled "normal").

Attack scenarios (all run against YOUR OWN test deployment's telemetry):
    invocation_flood    rapid-fire calls from one source (DoS / denial-of-wallet)
    payload_abuse       20-100x normal payload (oversized-input abuse)
    unauthorized_call   a function called by a caller outside the call graph
    auth_bruteforce     burst of 401s against auth-check
    resource_abuse      8-20x normal duration (cryptomining / ReDoS-like)
    low_and_slow        deliberately subtle: ~3x payload, 1.6x duration (hard case)

This is event-level telemetry only; nothing here attacks a real system.
"""
from __future__ import annotations

import math
import os
import random
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ssmf.models import Event  # noqa: E402

PROFILES = {
    "auth-check":      dict(payload=250,     p_sigma=0.35, dur=25,  d_sigma=0.30, callers=[("external", 1.0)]),
    "payment-process": dict(payload=600,     p_sigma=0.35, dur=120, d_sigma=0.30, callers=[("external", 0.7), ("auth-check", 0.3)]),
    "image-resize":    dict(payload=120_000, p_sigma=0.35, dur=250, d_sigma=0.30, callers=[("external", 0.8), ("notify-user", 0.2)]),
    "notify-user":     dict(payload=300,     p_sigma=0.35, dur=40,  d_sigma=0.30, callers=[("external", 0.5), ("payment-process", 0.3), ("image-resize", 0.2)]),
    "data-export":     dict(payload=15_000,  p_sigma=0.35, dur=300, d_sigma=0.30, callers=[("external", 0.75), ("auth-check", 0.25)]),
}
FUNCTIONS = list(PROFILES)
ALLOWED = {fn: {c for c, _ in p["callers"]} for fn, p in PROFILES.items()}
ATTACK_TYPES = ["invocation_flood", "payload_abuse", "unauthorized_call",
                "auth_bruteforce", "resource_abuse", "low_and_slow"]

CLIENT_IPS = [f"10.1.0.{i}" for i in range(1, 41)]
POD_IPS = [f"10.244.0.{i}" for i in range(10, 20)]
ATTACKER_IPS = ["203.0.113.9", "203.0.113.14", "203.0.113.27"]


def _lognorm(rng: random.Random, median: float, sigma: float) -> float:
    return median * math.exp(rng.gauss(0.0, sigma))


def _ev(t, fn, caller, ip, status, payload, dur, label):
    return Event(invocation_id=uuid.uuid4().hex[:12], timestamp=t, function_name=fn, caller=caller,
                 source_ip=ip, status_code=status, duration_ms=round(dur, 3),
                 payload_size_bytes=max(1, int(payload)), label=label)


def _normal_event(rng: random.Random, t: float) -> Event:
    fn = rng.choice(FUNCTIONS)
    p = PROFILES[fn]
    callers, weights = zip(*p["callers"])
    caller = rng.choices(callers, weights)[0]
    ip = rng.choice(CLIENT_IPS) if caller == "external" else rng.choice(POD_IPS)
    r = rng.random()
    if fn == "auth-check" and r < 0.03:
        status = 401
    elif r < 0.05:
        status = rng.choice([400, 404, 422])
    elif r < 0.06:
        status = 500
    else:
        status = 200
    return _ev(t, fn, caller, ip, status, _lognorm(rng, p["payload"], p["p_sigma"]),
               _lognorm(rng, p["dur"], p["d_sigma"]), "normal")


def _attack_burst(rng: random.Random, kind: str, t0: float, burst_id: int) -> list:
    label = f"{kind}#{burst_id}"
    ip = rng.choice(ATTACKER_IPS)
    out: list = []

    def run(n, rate, build):
        t = t0
        for _ in range(n):
            t += rng.expovariate(rate)
            out.append(build(t))

    if kind == "invocation_flood":
        fn = rng.choice(FUNCTIONS)
        p = PROFILES[fn]
        run(rng.randint(300, 600), rng.uniform(150, 300),
            lambda t: _ev(t, fn, "external", ip, 200, _lognorm(rng, p["payload"], p["p_sigma"]),
                          _lognorm(rng, p["dur"], p["d_sigma"]), label))
    elif kind == "payload_abuse":
        fn = rng.choice(["auth-check", "payment-process", "data-export", "notify-user"])
        p = PROFILES[fn]
        run(rng.randint(15, 40), 2.0,
            lambda t: _ev(t, fn, rng.choice(sorted(ALLOWED[fn])), ip, 200,
                          p["payload"] * rng.uniform(20, 100), _lognorm(rng, p["dur"] * 1.3, 0.3), label))
    elif kind == "unauthorized_call":
        fn = rng.choice(FUNCTIONS)
        bad = [c for c in FUNCTIONS if c not in ALLOWED[fn] and c != fn]
        caller = rng.choice(bad)
        p = PROFILES[fn]
        run(rng.randint(10, 25), 3.0,
            lambda t: _ev(t, fn, caller, ip, 200, _lognorm(rng, p["payload"], p["p_sigma"]),
                          _lognorm(rng, p["dur"], p["d_sigma"]), label))
    elif kind == "auth_bruteforce":
        p = PROFILES["auth-check"]
        run(rng.randint(40, 80), 8.0,
            lambda t: _ev(t, "auth-check", "external", ip, 401, _lognorm(rng, p["payload"], 0.2),
                          _lognorm(rng, p["dur"] * 0.8, 0.2), label))
    elif kind == "resource_abuse":
        fn = rng.choice(["image-resize", "data-export"])
        p = PROFILES[fn]
        run(rng.randint(15, 30), 1.0,
            lambda t: _ev(t, fn, "external", ip, 200, _lognorm(rng, p["payload"], p["p_sigma"]),
                          p["dur"] * rng.uniform(8, 20), label))
    elif kind == "low_and_slow":
        fn = rng.choice(["data-export", "payment-process"])
        p = PROFILES[fn]
        run(40, 1.5,
            lambda t: _ev(t, fn, "external", ip, 200, p["payload"] * rng.uniform(2.5, 3.5),
                          _lognorm(rng, p["dur"] * 1.6, 0.25), label))
    else:
        raise ValueError(f"unknown attack type {kind}")
    return out


def generate(n_normal: int = 5000, seed: int = 1, start: float = 1_700_000_000.0, rate: float = 30.0,
             bursts_per_type: int = 0) -> list:
    """Time-ordered events: `n_normal` background events plus `bursts_per_type` bursts of each attack."""
    rng = random.Random(seed)
    events, t = [], start
    for _ in range(n_normal):
        t += rng.expovariate(rate)
        events.append(_normal_event(rng, t))
    span = t - start

    if bursts_per_type > 0:
        kinds = [k for k in ATTACK_TYPES for _ in range(bursts_per_type)]
        rng.shuffle(kinds)
        slot = span / len(kinds)
        for i, kind in enumerate(kinds):
            t0 = start + i * slot + rng.uniform(1.0, max(1.5, slot * 0.25))
            events.extend(_attack_burst(rng, kind, t0, i))
    events.sort(key=lambda e: e.timestamp)
    return events


if __name__ == "__main__":
    evs = generate(2000, seed=3, bursts_per_type=1)
    from collections import Counter
    print(Counter(e.label.split("#")[0] for e in evs))
