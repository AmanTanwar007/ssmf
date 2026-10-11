# SSMF - Serverless Security Monitoring Framework

Real-time, function-aware security monitoring for open-source FaaS platforms (OpenFaaS / Knative).

Generic Kubernetes monitoring was designed for long-running pods, not for functions that start, run for
milliseconds and vanish. SSMF adds the missing layer: every invocation is instrumented, correlated against
a declared call-graph policy, scored by an unsupervised model that learns each function's normal behaviour,
and turned into de-duplicated, severity-ranked alerts on a live dashboard.

```
 serverless functions                         SSMF monitor (one service)
 ┌──────────────────────┐   HTTPS + API key   ┌──────────────────────────────────────────────┐
 │ @monitored handlers  │ ──────────────────► │ validate → detection engine → store → alerts │
 │ (zero-dependency SDK)│   batched events    │            rules  +  ML (LOF)                │
 └──────────────────────┘                     └───────┬──────────────┬───────────────┬───────┘
   signed caller identity                             ▼              ▼               ▼
                                                 dashboard      /metrics      webhook / JSONL
                                                 (live, /)     (Prometheus)   (Slack-compatible)
```

## What is in the box

| Component | Where | What it does |
|---|---|---|
| Instrumentation SDK | `sdk/ssmf_sdk.py` | `@monitored` decorator; async batched reporting; **signed caller identity** (HMAC) so a forged caller is recorded as `spoofed:<name>`; never breaks the function if the monitor is down. Zero dependencies. |
| Detection engine | `ssmf/engine.py`, `rules.py`, `ml.py`, `state.py` | Six explainable rules + an unsupervised ML detector (LOF by default, Isolation Forest and Mahalanobis selectable), O(1) per-event streaming state, baseline-poisoning guard. |
| Alerting | `ssmf/alerting.py` | One alert per (function, rule, source) with cooldown folding; log, JSONL and Slack-compatible webhook sinks; a dead sink can never stop detection. |
| API + dashboard | `ssmf/api.py`, `ssmf/static/` | Validated ingest, queries, Prometheus `/metrics`, interactive single-page console (overview, filterable alerts with detail drawer, live feed, call graph, CSV export, dark/light theme; no CDN, works offline, XSS-safe). |
| Sample functions | `functions/` | Five OpenFaaS `python3-http` functions + `stack.yml`. |
| Deployment | `Dockerfile`, `docker-compose.yml`, `deploy/k8s/` | Hardened container (non-root, read-only FS), Kubernetes manifests with NetworkPolicy. |
| Evaluation | `tools/simulator.py`, `tools/evaluate.py` | Labelled attack simulator and a reproducible benchmark (5 seeds). |
| Demo | `tools/local_demo.py` | Real handlers → SDK → HTTP → monitor with a five-phase attack scenario. |
| Tests | `tests/` | 60 tests: rules, ML, alerting, storage, config, API security, SDK. |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

python -m pytest tests -q                               # 60 tests
python tools/local_demo.py --with-monitor --keep-running   # full end-to-end demo, then open http://127.0.0.1:8000
python tools/evaluate.py                                # regenerates docs/EVALUATION.md + charts (about 1-2 min)
```

Run the monitor on its own and send it events:

```bash
SSMF_API_KEY=change-me uvicorn ssmf.api:create_app --factory --port 8000
curl -X POST localhost:8000/api/v1/events -H 'X-SSMF-Key: change-me' -H 'Content-Type: application/json' \
     -d '[{"function_name":"payment-process","caller":"image-resize","source_ip":"203.0.113.9"}]'
curl localhost:8000/api/v1/alerts
```

Docker: `SSMF_API_KEY=change-me docker compose up --build`. OpenFaaS on Kubernetes: `docs/DEPLOYMENT.md`.

## Detection rules

| Rule | Catches | Risk class |
|---|---|---|
| `INVOCATION_FLOOD` | One source hammering functions; concentrated volume on one function | Denial of service / denial of wallet |
| `AUTH_BRUTEFORCE` | Repeated 401/403 from one source (across all functions) | Broken authentication |
| `UNAUTHORIZED_CALL` | Caller not allowed by the call graph, or a forged caller identity | Business-logic abuse, lateral movement |
| `PAYLOAD_ANOMALY` | Over the policy cap, or a statistical outlier for that function | Oversized input / injection staging |
| `DURATION_ANOMALY` | Execution time far above that function's norm | Resource abuse (cryptomining, ReDoS-style) |
| `ERROR_SPIKE` | Burst of 5xx from one function | Exploit probing |
| `ML_ANOMALY` | Statistically unusual behaviour no explicit rule describes | Unknown / subtle abuse |

## Measured results

Five seeds x 20,000 events + 18 injected attack bursts per seed (6 attack types x 3), warm-up on a separate clean
baseline, evaluation seeds different from tuning seeds. Full tables, charts, speed and SDK overhead:
**`docs/EVALUATION.md`**.

| Mode | Precision | Recall | F1 | False-positive rate | Attack bursts detected |
|---|---|---|---|---|---|
| rules | 99.9% | 86.2% | 92.5% | 0.01% | 75 / 90 |
| ml (LOF) | 96.2% | 88.4% | 92.1% | 0.34% | 75 / 90 |
| **hybrid (default)** | 96.3% | **91.4%** | **93.7%** | 0.35% | **90 / 90** |

* Rules never fire on the deliberately subtle `low_and_slow` attack; the ML model catches about half of it.
  The model cannot learn call-graph violations (`unauthorized_call`, 0% ML-only); rules catch all of them. Hybrid covers both.
* **Isolation Forest** (the usual first choice) reached only ~12% recall here because it scores far-out-of-range points
  barely lower than normal ones; LOF reaches 88%. That finding is why the algorithm is configurable and LOF is the default.

## Design decisions worth knowing

* **Source-attributed alerting.** Flood detection flags the abusive *source*, so legitimate clients hitting the same
  function during an attack are not flagged, and a legitimate traffic surge spread over many clients does not alert.
  (Regression-tested.)
* **Baseline-poisoning guard.** Flagged events never update a function's baseline, so an attacker cannot slowly drag
  "normal" towards the attack.
* **ML persistence filter.** An ML-only alert needs the same source flagged twice within the window: attacks are
  bursts, false positives are isolated. This cut the ML false-positive rate from 1.27% to 0.34%.
* **Signed caller identity.** A plain `X-Caller-Function` header is trivially forgeable; with `SSMF_CALLER_SECRET` set,
  callers send a time-stamped HMAC and unverifiable identities become `spoofed:*`.
* **The monitor defends itself.** Pattern-validated identifiers (no log/metric/HTML injection), 1 MB / 1000-event
  limits, constant-time API-key check, security headers, bounded memory under spoofed-source floods, `textContent`-only rendering.

## Honest limitations

* **Synthetic evaluation.** Metrics come from `tools/simulator.py`. Treat them as indicative; validate on a real
  OpenFaaS/Knative deployment before quoting them as production figures.
* **Not run on a live cluster in the authoring environment.** The Docker, Compose and Kubernetes files are syntax-validated
  and the policy ConfigMap is checked against the shipped policy, but they were not executed. The end-to-end path
  (real handlers -> SDK -> HTTP -> monitor) was executed locally; see `docs/DEPLOYMENT.md` for the cluster steps.
* **Single replica.** Detection state is in memory; scaling out needs sharding by function or an external state store.
* **Thin distributed floods.** A flood spread over thousands of sources, each below the per-source limit, needs
  platform-level rate limiting; SSMF is not a WAF.
* **Learning period.** The ML model needs ~800 clean events before it activates (the dashboard shows progress); rules work immediately.
* **Read endpoints are unauthenticated** by default (ingest and admin require the API key); put the dashboard behind your
  ingress authentication in production.

## Documentation

* `docs/ARCHITECTURE.md` - components, data flow, detection design, threat model of the monitor itself
* `docs/EVALUATION.md` - generated results with methodology and caveats
* `docs/DEPLOYMENT.md` - local, Docker, and OpenFaaS-on-Kubernetes deployment
* `docs/DEMO_SCRIPT.md` - evaluator walkthrough and likely viva questions

*Referencing note for the report: this repository's text and code are original work. Cite external sources you
rely on (for example the OWASP Serverless Top 10 and the papers from your literature survey) in your own report.*
