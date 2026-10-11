# Evaluator walkthrough (about 8 minutes) and viva preparation

## Before the session (do this the day before)
* `pip install -r requirements-dev.txt && python -m pytest tests -q` shows `60 passed`.
* Push the repo to GitHub; keep the link for the Google Form ("Project implementation link").
* Run the demo once end to end so you have seen it work on *your* machine.
* Have `docs/EVALUATION.md` and the two charts in `results/` open in tabs.

## Live demo
| Min | Do | Say |
|---|---|---|
| 0:00 | Show the architecture diagram (README) | "Pod-level monitoring can't see invocations. SSMF instruments each function, correlates against a declared call graph, and adds an ML model that learns each function's normal behaviour." |
| 1:00 | `python tools/local_demo.py --with-monitor --keep-running`, open http://127.0.0.1:8000 | "These are the real sample functions, going through the real SDK over HTTP to a real monitor." |
| 1:30 | Dashboard during the learning period | "Rules are live immediately. The ML model shows `learning x/800` and activates after 800 clean events." |
| 3:00 | Attack phases scroll by (console and dashboard) | One line per phase: flood, brute force, unauthorized + **forged caller**, oversized payload, resource abuse. "Each gets its own alert; repeats are folded into one." |
| 5:00 | Console summary: about 11 alerts from about 1,660 invocations | "No ML noise on legitimate clients: persistence filter, low severity for ML-only." |
| 6:00 | `docs/EVALUATION.md` + recall chart | Quote the hybrid row; point at `low_and_slow` (rules 0%, ML ~50%) and `unauthorized_call` (ML 0%, rules 100%). |
| 7:00 | Open `ssmf/rules.py` and `tests/test_rules.py` | "Every alert carries its reason; the flood-attribution fix is covered by a regression test I verified fails if the bug returns." |

If the live demo fails: `python -m pytest tests -q` (60 pass) and the pre-generated `docs/EVALUATION.md` are your fallback.

## Likely questions, and honest answers
**Why not just Prometheus and Grafana?** They describe containers. They cannot say "image-resize called payment-process, which the call graph forbids", nor attribute a flood to one source.

**Why hybrid?** Measured, not assumed: rules never detect the subtle low-and-slow attack, the model never learns call-graph violations. Hybrid is best on F1 (93.7%) and the only mode that detects all 90 attack bursts.

**Why LOF and not Isolation Forest?** I ran all three. Isolation Forest reached ~12% recall because it scores far-out-of-range points only marginally lower than normal; LOF reached ~88%. The algorithm is configurable.

**Is it overfitted to your simulator?** Evaluation seeds differ from tuning seeds, but the generator family is the same, so absolute numbers are indicative. The next step is validating on a real OpenFaaS/Knative deployment; I say so in the report.

**False positives?** 0.35% event-level in hybrid. Controls: held-out threshold calibration, a persistence filter (the same source flagged twice), ML-only alerts ranked low, and cooldown folding.

**What if the monitor is down?** The SDK queue is bounded and sheds events; the function is never slowed or broken (tested).

**Can an attacker evade it?** Yes, and I measured one case: low-and-slow stays under every rule. Also thin distributed floods, and slow baseline drift (mitigated: flagged events never train the baseline). It is a detector, not a blocker.

**Can the caller header be spoofed?** Unsigned, yes, so the SDK supports an HMAC with a freshness window; forgeries are recorded as `spoofed:*` and flagged.

**Overhead?** Microseconds per call on the function side (`docs/EVALUATION.md`, section 5), sent asynchronously. Quote it as "order of microseconds", since timings on my machine are noisy.

**What is novel?** Position it against *your own* literature survey. A defensible framing: inline function-level correlation for self-hosted FaaS, combining a declared call-graph policy, signed caller identity and an adaptive model, with a measured rules-vs-ML comparison. Check each claim against the papers you cited before you say it.

**What would you do next?** Run on a live cluster, replay real traces, add per-function adaptive thresholds, shard state for horizontal scale.

## Google Form checklist
1. Project ID (BT1-BT278) from your approval form.
2. Guide has verified your work: **Yes** only after the guide has seen the demo.
3. Implementation link: your GitHub repository URL.
```bash
git init && git add . && git commit -m "SSMF: serverless security monitoring framework"
git branch -M main && git remote add origin https://github.com/<you>/<repo>.git && git push -u origin main
```
