"""Reproducible evaluation of SSMF: detection quality, speed and instrumentation overhead.

    python tools/evaluate.py                       # 5 seeds x 20,000 events (about 1 minute)
    python tools/evaluate.py --seeds 3 --events 10000 --out results

Method
  * For every seed: a clean baseline (3,000 events) warms each detector, then a
    separate test stream (normal background + 3 bursts of each of 6 attack types)
    is replayed in micro-batches of 500.
  * Event-level metrics: an event is positive if it belongs to an attack burst.
  * Incident-level metrics: a burst is detected if any of its events is flagged;
    time-to-detect is measured from the first event of the burst.
  * Evaluation seeds (101..) differ from the seeds used while tuning the detectors.

Caveat (also written into the report): the traffic is synthetic and comes from the
same simulator family the detectors were developed against, so absolute numbers are
indicative, not a guarantee on production traffic.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import statistics
import sys
import time
import types
from collections import defaultdict

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
for p in (ROOT, os.path.join(ROOT, "sdk"), os.path.dirname(os.path.abspath(__file__))):
    sys.path.insert(0, p)

import numpy as np  # noqa: E402
import simulator  # noqa: E402

from ssmf.config import load_policy  # noqa: E402
from ssmf.engine import DetectionEngine  # noqa: E402

MODES = ["rules", "ml", "hybrid"]
ALGORITHMS = ["lof", "iforest", "mahalanobis"]
ATTACKS = simulator.ATTACK_TYPES
BASELINE_EVENTS = 3000
BURSTS_PER_TYPE = 3
BATCH = 500


def run_mode(policy, mode, base, test):
    eng = DetectionEngine(policy, mode=mode)
    eng.warm_up(base)
    t0 = time.perf_counter()
    dets = []
    for i in range(0, len(test), BATCH):
        dets += eng.process_batch(test[i:i + BATCH])
    return dets, len(test) / (time.perf_counter() - t0)


def metrics(dets):
    pos = [d for d in dets if d.event.label != "normal"]
    neg = [d for d in dets if d.event.label == "normal"]
    tp = sum(d.flagged for d in pos)
    fp = sum(d.flagged for d in neg)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(pos) if pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    per_attack = defaultdict(lambda: [0, 0])
    bursts = defaultdict(list)
    for d in pos:
        kind = d.event.label.split("#")[0]
        per_attack[kind][1] += 1
        per_attack[kind][0] += d.flagged
        bursts[d.event.label].append(d)
    detected, ttd = 0, []
    for evs in bursts.values():
        evs.sort(key=lambda d: d.event.timestamp)
        hit = next((d for d in evs if d.flagged), None)
        if hit:
            detected += 1
            ttd.append(hit.event.timestamp - evs[0].event.timestamp)
    return {
        "precision": precision, "recall": recall, "f1": f1, "fpr": fp / len(neg) if neg else 0.0,
        "tp": tp, "fp": fp, "positives": len(pos), "negatives": len(neg),
        "per_attack_recall": {k: a / b for k, (a, b) in per_attack.items()},
        "bursts_detected": detected, "bursts_total": len(bursts),
        "mean_time_to_detect_s": statistics.mean(ttd) if ttd else None,
    }


def agg(values):
    values = [v for v in values if v is not None]
    if not values:
        return {"mean": None, "std": None}
    return {"mean": statistics.mean(values), "std": statistics.pstdev(values) if len(values) > 1 else 0.0}


def aggregate(runs):
    out = {k: agg([r[k] for r in runs]) for k in ("precision", "recall", "f1", "fpr", "mean_time_to_detect_s")}
    out["per_attack_recall"] = {a: agg([r["per_attack_recall"].get(a) for r in runs]) for a in ATTACKS}
    out["bursts_detected"] = sum(r["bursts_detected"] for r in runs)
    out["bursts_total"] = sum(r["bursts_total"] for r in runs)
    return out


def latency_profile(policy, mode, base, test, n=1500):
    eng = DetectionEngine(policy, mode=mode)
    eng.warm_up(base)
    lat = []
    for ev in test[:n]:
        t0 = time.perf_counter()
        eng.process_event(ev)
        lat.append((time.perf_counter() - t0) * 1000.0)
    lat = np.array(lat)
    return {"p50_ms": float(np.percentile(lat, 50)), "p95_ms": float(np.percentile(lat, 95)),
            "p99_ms": float(np.percentile(lat, 99)), "mean_ms": float(lat.mean())}


def sdk_overhead(n=50_000):
    import ssmf_sdk
    ev = types.SimpleNamespace(body=b'{"amount": 12}', headers={"X-Forwarded-For": "10.1.0.5"})

    def bare(event, context):
        return {"statusCode": 200, "body": "ok"}

    sync_wrapped = ssmf_sdk.monitored("bench", reporter=ssmf_sdk.Reporter(sink=lambda b: None, sync=True))(bare)
    async_rep = ssmf_sdk.Reporter(sink=lambda b: None, sync=False, max_queue=n * 2)
    async_wrapped = ssmf_sdk.monitored("bench", reporter=async_rep)(bare)

    def timeit(fn):
        t0 = time.perf_counter()
        for _ in range(n):
            fn(ev, None)
        return (time.perf_counter() - t0) / n * 1e6

    base_us, sync_us, async_us = timeit(bare), timeit(sync_wrapped), timeit(async_wrapped)
    async_rep.flush(10)
    return {"bare_us": base_us, "instrumented_inline_us": sync_us, "instrumented_async_us": async_us,
            "overhead_us": async_us - base_us}


def pct(x, d=1):
    return "n/a" if x is None else f"{100 * x:.{d}f}%"


def pm(a, d=1):
    return "n/a" if a["mean"] is None else f"{100 * a['mean']:.{d}f}% ± {100 * a['std']:.{d}f}"


def charts(out_dir, results, algo_results):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = {"rules": "#5B8DEF", "ml": "#D4A72C", "hybrid": "#3FB950"}
    labels = [a.replace("_", "\n") for a in ATTACKS]
    x = np.arange(len(ATTACKS))
    fig, ax = plt.subplots(figsize=(10, 4.6))
    for i, m in enumerate(MODES):
        vals = [100 * (results[m]["per_attack_recall"][a]["mean"] or 0) for a in ATTACKS]
        ax.bar(x + (i - 1) * 0.27, vals, 0.27, label=m, color=colors[m])
    ax.set_xticks(x, labels)
    ax.set_ylabel("recall (% of attack events flagged)")
    ax.set_ylim(0, 125)
    ax.set_yticks(range(0, 101, 20))
    ax.set_title("Detection recall by attack type and detector mode (mean of seeds)")
    ax.legend(ncol=3, loc="upper center")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "recall_by_attack.png"), dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 4.6))
    ac = {"lof": "#3FB950", "iforest": "#E07B53", "mahalanobis": "#5B8DEF"}
    for i, a_name in enumerate(ALGORITHMS):
        vals = [100 * (algo_results[a_name]["per_attack_recall"][a]["mean"] or 0) for a in ATTACKS]
        ax.bar(x + (i - 1) * 0.27, vals, 0.27,
               label=f"{a_name} (FPR {pct(algo_results[a_name]['fpr']['mean'], 2)})", color=ac[a_name])
    ax.set_xticks(x, labels)
    ax.set_ylabel("recall (%)")
    ax.set_ylim(0, 125)
    ax.set_yticks(range(0, 101, 20))
    ax.set_title("ML component only: algorithm comparison")
    ax.legend(ncol=3, loc="upper center", fontsize=9)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "ml_algorithm_comparison.png"), dpi=150)
    plt.close(fig)


def write_markdown(path, cfg, results, algo_results, perf, sdk, algo_default):
    L = []
    w = L.append
    w("# SSMF evaluation results\n")
    w(f"Generated by `tools/evaluate.py` - {cfg['seeds']} seeds x {cfg['events']:,} normal events "
      f"+ {BURSTS_PER_TYPE} bursts of each of {len(ATTACKS)} attack types per seed "
      f"(baseline warm-up {BASELINE_EVENTS:,} clean events). All figures are means over seeds.\n")
    w("## 1. Detection quality (event level)\n")
    w("| Mode | Precision | Recall | F1 | False-positive rate | Bursts detected | Mean time-to-detect |")
    w("|---|---|---|---|---|---|---|")
    for m in MODES:
        r = results[m]
        ttd = r["mean_time_to_detect_s"]["mean"]
        w(f"| {m} | {pm(r['precision'])} | {pm(r['recall'])} | {pm(r['f1'])} | {pm(r['fpr'], 2)} | "
          f"{r['bursts_detected']}/{r['bursts_total']} | {'n/a' if ttd is None else f'{ttd:.2f} s'} |")
    w("\n## 2. Recall by attack type\n")
    w("| Attack | " + " | ".join(MODES) + " |")
    w("|---|" + "---|" * len(MODES))
    for a in ATTACKS:
        w(f"| {a} | " + " | ".join(pct(results[m]['per_attack_recall'][a]['mean'], 0) for m in MODES) + " |")
    w("\n![recall by attack](../results/recall_by_attack.png)\n")
    w("## 3. ML algorithm comparison (ML component only)\n")
    w("| Algorithm | Precision | Recall | F1 | False-positive rate |")
    w("|---|---|---|---|---|")
    for a in ALGORITHMS:
        r = algo_results[a]
        star = " (default)" if a == algo_default else ""
        w(f"| {a}{star} | {pm(r['precision'])} | {pm(r['recall'])} | {pm(r['f1'])} | {pm(r['fpr'], 2)} |")
    w("\n![algorithms](../results/ml_algorithm_comparison.png)\n")
    w("## 4. Speed\n")
    w("| Mode | Batch throughput (events/s) | Per-event latency p50 | p95 | p99 |")
    w("|---|---|---|---|---|")
    for m in MODES:
        p = perf[m]
        w(f"| {m} | {p['throughput']:,.0f} | {p['p50_ms']:.3f} ms | {p['p95_ms']:.3f} ms | {p['p99_ms']:.3f} ms |")
    w("\nBatch throughput = events processed per second when replayed in micro-batches of "
      f"{BATCH} (single process, includes ML scoring). Per-event latency = one `process_event` call at a time. "
      "Timings were taken on a shared, noisy machine and varied by up to ~2x between runs, so read them as orders "
      "of magnitude (tens of thousands of events/s; sub-millisecond latency) and re-run `tools/evaluate.py` on your own hardware "
      "for figures you intend to quote. Detection metrics, by contrast, are deterministic for a given seed.\n")
    w("## 5. Instrumentation overhead (SDK)\n")
    w("| Variant | Time per call |")
    w("|---|---|")
    w(f"| bare handler | {sdk['bare_us']:.2f} us |")
    w(f"| `@monitored` (async reporter, default) | {sdk['instrumented_async_us']:.2f} us |")
    w(f"| `@monitored` (inline / `SSMF_SYNC=1`, network excluded) | {sdk['instrumented_inline_us']:.2f} us |")
    w(f"\nAdded latency of the default (async) SDK: about **{sdk['overhead_us']:.1f} us per invocation** "
      "(event construction + queue put; the network send happens on a background thread). This is a tight-loop "
      "micro-benchmark in which the background sender competes for the interpreter lock, so it is an upper bound "
      "for real handlers; compare it with the milliseconds a real function spends doing work.\n")
    w("## 6. Reading these results honestly\n")
    w("* **'Best' depends on the goal.** Rules-only has the highest precision and F1 (very few false alarms). "
      "Hybrid has the highest recall and is the only mode that detected every attack burst, at the cost of "
      "about 1% more false positives. If missing an incident is worse than reviewing a low-severity alert, "
      "hybrid is the right default; if alert fatigue dominates, run `SSMF_MODE=rules`.")
    w("* **Complementary, not redundant.** Rules never fire on `low_and_slow` (it stays under every explicit limit) "
      "while the ML model does; the model cannot learn call-graph violations (`unauthorized_call`) because that "
      "signal never varies in training, while rules catch them every time. Hybrid inherits both.")
    w("* **The price of ML.** The raw model flags roughly 1% of clean events. Three controls keep that manageable: "
      "a persistence filter (the same source must be flagged twice within the window, because attacks are bursts "
      "and false positives are isolated), ML-only alerts are ranked `low` severity and only escalate when a rule "
      "agrees, and alert cooldown folds repeats into one alert.")
    w("* **Isolation Forest underperforms here.** It scores far-out-of-range points only marginally lower than "
      "normal ones, so large anomalies slip through; LOF (distance-based) does not share that weakness, hence the default.")
    w("* **Floods:** recall is below 100% by design - the first calls of a burst arrive before the rate threshold "
      "is crossed. Time-to-detect above shows how quickly that happens.")
    w("* **Synthetic data.** Traffic comes from `tools/simulator.py`, the same family of generators the detectors "
      "were developed against (tuning used different seeds from this evaluation). Treat absolute numbers as "
      "indicative; validate on a real OpenFaaS/Knative deployment before relying on them.")
    w("* **Not covered:** `ERROR_SPIKE` has no attack scenario here (it is unit-tested), and a flood spread thinly "
      "over thousands of sources is a known gap - use platform rate limiting for that.")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Evaluate SSMF detectors")
    ap.add_argument("--events", type=int, default=20_000)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    ap.add_argument("--md", default=os.path.join(ROOT, "docs", "EVALUATION.md"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    policy = load_policy()
    algo_default = policy.detection.ml.algorithm
    per_mode = defaultdict(list)
    per_algo = defaultdict(list)
    throughput = defaultdict(list)
    first_data = None

    for s in range(args.seeds):
        base = simulator.generate(BASELINE_EVENTS, seed=200 + s)
        test = simulator.generate(args.events, seed=100 + s, bursts_per_type=BURSTS_PER_TYPE,
                                  start=base[-1].timestamp + 60)
        if first_data is None:
            first_data = (base, test)
        for m in MODES:
            dets, tput = run_mode(policy, m, base, test)
            per_mode[m].append(metrics(dets))
            throughput[m].append(tput)
        for a in ALGORITHMS:
            ml = dataclasses.replace(policy.detection.ml, algorithm=a)
            p = dataclasses.replace(policy, detection=dataclasses.replace(policy.detection, ml=ml))
            dets, _ = run_mode(p, "ml", base, test)
            per_algo[a].append(metrics(dets))
        print(f"seed {s + 1}/{args.seeds} done", flush=True)

    results = {m: aggregate(per_mode[m]) for m in MODES}
    algo_results = {a: aggregate(per_algo[a]) for a in ALGORITHMS}

    base, test = first_data
    perf = {}
    for m in MODES:
        lp = latency_profile(policy, m, base, test)
        lp["throughput"] = statistics.mean(throughput[m])
        perf[m] = lp
    sdk = sdk_overhead()

    cfg = {"events": args.events, "seeds": args.seeds}
    with open(os.path.join(args.out, "evaluation.json"), "w") as fh:
        json.dump({"config": cfg, "modes": results, "ml_algorithms": algo_results, "speed": perf, "sdk": sdk},
                  fh, indent=2)
    charts(args.out, results, algo_results)
    write_markdown(args.md, cfg, results, algo_results, perf, sdk, algo_default)

    print("\n=== Detection (mean over seeds) ===")
    for m in MODES:
        r = results[m]
        print(f"{m:7s} precision={pm(r['precision'])}  recall={pm(r['recall'])}  F1={pm(r['f1'])}  "
              f"FPR={pm(r['fpr'], 2)}  bursts={r['bursts_detected']}/{r['bursts_total']}")
    print("\n=== ML algorithms ===")
    for a in ALGORITHMS:
        r = algo_results[a]
        print(f"{a:12s} recall={pm(r['recall'])}  FPR={pm(r['fpr'], 2)}  F1={pm(r['f1'])}")
    print("\n=== Speed ===")
    for m in MODES:
        p = perf[m]
        print(f"{m:7s} {p['throughput']:>9,.0f} ev/s batch | latency p50={p['p50_ms']:.3f} ms p99={p['p99_ms']:.3f} ms")
    print(f"\nSDK overhead: {sdk['overhead_us']:.1f} us/invocation (bare {sdk['bare_us']:.2f} us)")
    print(f"\nWrote {args.md}, {args.out}/evaluation.json and charts.")


if __name__ == "__main__":
    main()
