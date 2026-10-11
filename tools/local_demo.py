"""End-to-end demo: real function handlers -> SDK -> HTTP -> monitor -> detection -> dashboard.

    python tools/local_demo.py --with-monitor          # starts the monitor too, then runs the scenario
    python tools/local_demo.py --url http://127.0.0.1:8000   # use a monitor that is already running

Timeline
  1. Learning period: normal traffic at ~25 requests/s so every function builds its baseline
     and the ML model trains (dashboard shows "ML learning x/800", then "active").
  2. Five attack phases, each followed by normal traffic:
        flood  ->  brute force  ->  unauthorized calls (incl. a forged caller)  ->
        oversized payloads  ->  resource abuse
  3. A summary of what was detected.

All "attacks" are requests against the sample functions on your own machine; they exist to
exercise the detector and are limited to a few hundred cheap calls.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import types
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "sdk"))

CLIENT_IPS = [f"10.1.0.{i}" for i in range(1, 21)]
POD_IPS = [f"10.244.0.{i}" for i in range(10, 16)]
ATTACKER = "203.0.113.9"
FUNCTIONS = ["auth-check", "payment-process", "image-resize", "notify-user", "data-export"]
ALLOWED_CALLERS = {            # mirrors ssmf/default_policy.yaml
    "auth-check": ["external"],
    "payment-process": ["external", "auth-check"],
    "image-resize": ["external", "notify-user"],
    "notify-user": ["external", "payment-process", "image-resize"],
    "data-export": ["external", "auth-check"],
}


def load_handlers() -> dict:
    handlers = {}
    for fn in FUNCTIONS:
        path = os.path.join(ROOT, "functions", fn, "handler.py")
        spec = importlib.util.spec_from_file_location("fn_" + fn.replace("-", "_"), path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        handlers[fn] = mod.handle
    return handlers


class Caller:
    """Builds requests the way a gateway / calling function would."""

    def __init__(self, handlers: dict) -> None:
        self.h = handlers

    def call(self, fn, body=b"", ip=None, caller="external", signed=True, extra=None):
        import ssmf_sdk
        headers = {"X-Forwarded-For": ip or random.choice(CLIENT_IPS), "X-Call-Id": f"d{random.getrandbits(40):010x}"}
        if caller != "external":
            headers.update(ssmf_sdk.caller_headers(caller) if signed else {"X-Caller-Function": caller})
        headers.update(extra or {})
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        event = types.SimpleNamespace(body=body, headers=headers, method="POST", query={}, path="/")
        try:
            return self.h[fn](event, None)
        except Exception:                       # the SDK already reported the 500
            return {"statusCode": 500}

    # ---- normal traffic ---------------------------------------------------
    def normal(self):
        fn = random.choice(FUNCTIONS)
        caller = random.choices(ALLOWED_CALLERS[fn], weights=[6] + [2] * (len(ALLOWED_CALLERS[fn]) - 1))[0]
        ip = random.choice(CLIENT_IPS) if caller == "external" else random.choice(POD_IPS)
        user = random.choice(["alice", "bob"])
        if fn == "auth-check":
            ok = random.random() > 0.03
            return self.call(fn, {"user": user, "password": f"{user}-pass" if ok else "wrong" + "x" * random.randint(0, 6)}, ip, caller)
        if fn == "payment-process":
            return self.call(fn, {"user": user, "amount": round(random.uniform(5, 500), 2),
                                  "memo": "m" * random.randint(0, 150)}, ip, caller)
        if fn == "image-resize":
            size = int(random.lognormvariate(11.5, 0.4))
            return self.call(fn, bytes(size), ip, caller, extra={"X-Quality": str(random.randint(5, 20))})
        if fn == "notify-user":
            return self.call(fn, {"user": user, "message": "n" * random.randint(20, 300)}, ip, caller)
        return self.call(fn, {"rows": random.randint(20, 80)}, ip, caller)


def traffic(c: Caller, seconds: float, pace: float):
    end, nxt = time.time() + seconds, time.time()
    while time.time() < end:
        c.normal()
        nxt += 1.0 / pace
        time.sleep(max(0.0, nxt - time.time()))


# ------------------------------------------------------------------- attacks
def attack_flood(c):
    for _ in range(150):
        c.call("payment-process", {"user": "alice", "amount": 20, "memo": "m" * 40}, ATTACKER)


def attack_bruteforce(c):
    for i in range(30):
        c.call("auth-check", {"user": "alice", "password": f"guess{i:04d}"}, ATTACKER)
        time.sleep(0.1)


def attack_unauthorized(c):
    for _ in range(6):   # legitimately signed, but image-resize may not call payment-process
        c.call("payment-process", {"user": "bob", "amount": 50, "memo": "m" * 50}, random.choice(POD_IPS), caller="image-resize")
        time.sleep(0.15)
    for _ in range(6):   # forged identity: claims to be auth-check without a valid signature
        c.call("data-export", {"rows": 40}, ATTACKER, caller="auth-check", signed=False)
        time.sleep(0.15)


def attack_payload(c):
    for _ in range(8):
        c.call("data-export", {"rows": 50, "pad": "A" * 700_000}, ATTACKER)
        time.sleep(0.4)


def attack_resource(c):
    for _ in range(10):
        c.call("image-resize", bytes(120_000), ATTACKER, extra={"X-Quality": "300000"})
        time.sleep(0.3)


PHASES = [
    ("Invocation flood (denial-of-wallet style)", attack_flood),
    ("Credential brute force against auth-check", attack_bruteforce),
    ("Unauthorized call chain + forged caller identity", attack_unauthorized),
    ("Oversized payloads to data-export", attack_payload),
    ("Resource abuse: image-resize work-factor abuse", attack_resource),
]


# ----------------------------------------------------------------------- main
def wait_for(url: str, timeout: float = 25.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url + "/health", timeout=1).read()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def get_json(url: str):
    return json.loads(urllib.request.urlopen(url, timeout=5).read())


def main():
    ap = argparse.ArgumentParser(description="SSMF end-to-end demo")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--with-monitor", action="store_true", help="start the monitor in a subprocess")
    ap.add_argument("--warmup-seconds", type=float, default=40.0)
    ap.add_argument("--gap-seconds", type=float, default=8.0, help="normal traffic between attack phases")
    ap.add_argument("--pace", type=float, default=25.0, help="normal requests per second")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--keep-running", action="store_true", help="with --with-monitor: keep serving until Ctrl-C")
    args = ap.parse_args()

    server = None
    if args.with_monitor:
        port = args.url.rsplit(":", 1)[-1]
        env = dict(os.environ, SSMF_DB=os.path.join(tempfile.mkdtemp(), "demo.db"), SSMF_API_KEY=args.api_key)
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "ssmf.api:create_app", "--factory", "--port", port, "--log-level", "warning"],
            cwd=ROOT, env=env)
    if not wait_for(args.url):
        print(f"Cannot reach a monitor at {args.url}. Start one with:\n"
              f"  uvicorn ssmf.api:create_app --factory --port 8000\n(or pass --with-monitor)")
        if server:
            server.terminate()
        sys.exit(1)

    os.environ["SSMF_MONITOR_URL"] = args.url
    os.environ["SSMF_CALLER_SECRET"] = "demo-caller-secret"       # enables signed caller identity
    if args.api_key:
        os.environ["SSMF_API_KEY"] = args.api_key
    random.seed(7)

    print(f"\nDashboard: {args.url}/\n")
    c = Caller(load_handlers())
    try:
        print(f"[1/2] Learning period: {args.warmup_seconds:.0f}s of normal traffic at ~{args.pace:.0f} req/s ...")
        traffic(c, args.warmup_seconds, args.pace)
        eng = get_json(args.url + "/api/v1/stats")["engine"]
        print(f"      ML model: {'active' if eng['ml_ready'] else 'still learning'} "
              f"({eng['ml_warmup_done']}/{eng['ml_warmup_needed']} clean events)")

        print("[2/2] Attack scenario")
        for i, (name, fn) in enumerate(PHASES, 1):
            print(f"  phase {i}/{len(PHASES)}: {name}")
            fn(c)
            traffic(c, args.gap_seconds, args.pace)

        import ssmf_sdk
        ssmf_sdk.get_reporter().flush(5)
        time.sleep(1.0)
        stats = get_json(args.url + "/api/v1/stats")
        alerts = get_json(args.url + "/api/v1/alerts?limit=100")
        print(f"\nProcessed {stats['total_events']:,} invocations -> {stats['total_alerts']} alerts "
              f"({stats['suppressed_duplicates']} duplicate detections folded).")
        print("Alerts by rule:")
        for r in stats["by_rule"]:
            print(f"  {r['rule']:<20} {r['count']}")
        print("\nMost recent alerts:")
        for a in alerts[:12]:
            print(f"  [{a['severity']:<8}] {a['rule']:<18} {a['function_name']:<16} from {a['source_ip']:<14} {a['message'][:70]}")
        if server and args.keep_running:
            print(f"\nMonitor still running at {args.url}/ - press Ctrl-C to stop.")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.terminate()


if __name__ == "__main__":
    main()
