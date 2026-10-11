# Deployment guide

Three ways to run SSMF, from "works on a laptop in two minutes" to "monitoring real OpenFaaS functions".

> **Status of each path.** A is executed and tested. B and C ship as ready-to-use files that were syntax-validated
> but **not executed** where this project was written (no Docker daemon or cluster was available). Run them early
> and fix anything environment-specific before your demo day.

## A. Local (tested)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests -q
python tools/local_demo.py --with-monitor --keep-running      # then open http://127.0.0.1:8000
```

The demo runs the five sample functions in-process through the real SDK against a real HTTP monitor.

## B. Docker Compose (not executed here)

```bash
export SSMF_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
# dashboard: http://localhost:8000   health: http://localhost:8000/health
```
Point any function or script at it: `SSMF_MONITOR_URL=http://localhost:8000 SSMF_API_KEY=$SSMF_API_KEY`.

## C. OpenFaaS on Kubernetes (not executed here)

Prerequisites: Docker, `kubectl`, a local cluster (k3d or kind), `arkade`, `faas-cli`.

```bash
# 1. Cluster + OpenFaaS
k3d cluster create ssmf                       # or: kind create cluster --name ssmf
curl -sLS https://get.arkade.dev | sudo sh
arkade install openfaas && arkade get faas-cli
kubectl rollout status -n openfaas deploy/gateway
kubectl port-forward -n openfaas svc/gateway 8080:8080 &
PASSWORD=$(kubectl get secret -n openfaas basic-auth -o jsonpath="{.data.basic-auth-password}" | base64 --decode)
echo -n "$PASSWORD" | faas-cli login --username admin --password-stdin

# 2. Build and load the monitor image, deploy the monitor
docker build -t ssmf-monitor:latest .
k3d image import ssmf-monitor:latest -c ssmf          # kind: kind load docker-image ssmf-monitor:latest --name ssmf
#   edit deploy/k8s/ssmf-monitor.yaml: image: ssmf-monitor:latest, add "imagePullPolicy: IfNotPresent",
#   and set the Secret's `key` to a long random string
kubectl apply -f deploy/k8s/ssmf-monitor.yaml
kubectl -n ssmf rollout status deploy/ssmf-monitor

# 3. Secrets the functions read (mounted at /var/openfaas/secrets/<name>; the SDK reads them automatically)
faas-cli secret create ssmf-api-key --from-literal="THE-SAME-KEY-AS-IN-THE-SECRET-ABOVE"
faas-cli secret create ssmf-caller-secret --from-literal="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# 4. Deploy the sample functions with the SDK vendored in
faas-cli template store pull python3-http
./functions/vendor_sdk.sh
#   edit functions/stack.yml: replace YOUR_REGISTRY with a registry the cluster can pull from
#   (for a purely local cluster, build with `faas-cli build` and import each image as in step 2)
cd functions && faas-cli up -f stack.yml && cd ..

# 5. Send traffic and watch
curl -s -X POST http://127.0.0.1:8080/function/auth-check -d '{"user":"alice","password":"alice-pass"}'
kubectl port-forward -n ssmf svc/ssmf-monitor 8000:8000        # dashboard: http://127.0.0.1:8000
```

### Connecting your own functions
1. Copy `sdk/ssmf_sdk.py` into the function folder (or vendor it as above).
2. Decorate the handler: `@monitored("my-function")`.
3. Set `SSMF_MONITOR_URL`; mount `ssmf-api-key` (and `ssmf-caller-secret` if you want signed caller identity).
4. When one function calls another, add `**caller_headers("my-function")` to the request headers.
5. Declare the function and its allowed callers in `ssmf/default_policy.yaml` (or your own policy via `SSMF_POLICY`).

### Knative (adaptation, untested)
The SDK only needs an object exposing `.headers` and `.body`, so a thin web-framework shim is enough:

```python
from flask import Flask, request
from types import SimpleNamespace
from ssmf_sdk import monitored

app = Flask(__name__)

@monitored("my-service")
def handle(event, context):
    return {"statusCode": 200, "body": "ok"}

@app.route("/", methods=["POST"])
def entry():
    out = handle(SimpleNamespace(body=request.get_data(), headers=dict(request.headers)), None)
    return out["body"], out["statusCode"]
```
Knative's queue-proxy sets `X-Forwarded-For`; confirm what your ingress forwards before trusting `source_ip`.

### Troubleshooting
| Symptom | Likely cause |
|---|---|
| Dashboard empty | Functions cannot reach the monitor: check `SSMF_MONITOR_URL`, the NetworkPolicy (allows `openfaas-fn`), and function logs for `[ssmf_sdk] could not reach monitor` |
| Function logs show the warning above and monitor logs 401 | API key mismatch between the monitor Secret and the `ssmf-api-key` function secret |
| Every internal call is `UNAUTHORIZED_CALL` / `spoofed:*` | `ssmf-caller-secret` differs between functions, or callers do not send `caller_headers(...)` |
| "ML learning x/800" for a long time | Low traffic: the model needs ~800 clean events; rules are active meanwhile |
| Many `DURATION_ANOMALY` alerts on very fast functions | Sub-millisecond durations are timing noise; raise `min_log_std` in the policy |
| All traffic shows one source IP | Your gateway/ingress is not forwarding `X-Forwarded-For` |
