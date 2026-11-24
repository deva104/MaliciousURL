# Step 3: Deployment Guide (REST API, Docker, Render)

**Project:** Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)
**Code:**
- `api/main.py`: FastAPI app
- `src/predict.py`: inference
- `src/trusted_domains.py`: safety net
- `Dockerfile`, `render.yaml`, `requirements-api.txt`

**Live API:** `https://malicious-url-api.onrender.com` (Swagger UI at `/docs`)

---

## 1. Architecture

```
 Chrome extension (Step 4)             Render free web service (Docker, Singapore)
 ┌──────────────────────┐   HTTPS     ┌──────────────────────────────────────────────────────────┐
 │ every visited URL ───┼──POST──────►│ FastAPI (api/main.py)                                     │
 │ shows verdict/badge ◄┼──JSON───────┤  ├─ validation (Pydantic: empty / >2000 chars / no host)  │
 └──────────────────────┘             │  ├─ LRU cache (10k normalised URLs)                        │
                                      │  ├─ trusted-domain list (src/trusted_domains.py)           │
                                      │  └─ src/predict.py ─► src/features.py (same code as Step 1)│
                                      │       └─ models/feature_extractor.joblib + best_model.joblib│
                                      └──────────────────────────────────────────────────────────┘
```

* **Model:** Soft Voting of a tuned 50-tree Random Forest, tuned XGBoost and LightGBM, trained
  without the documented noisy rows, at threshold **0.80** (Step 2). It is 13.3 MB on disk and
  ~14 ms per URL on one thread.
* **No duplicated feature code.** The API calls `src/predict.py`, which uses the saved
  `UrlFeatureExtractor` (Step 1). `load_artifacts()` checks the feature list against the SHA-256
  stored in `model_metadata.json`.
* The artifacts are **loaded once at start-up** (FastAPI lifespan), followed by one warm-up
  prediction.

## 2. Endpoints

| method | path | purpose |
|---|---|---|
| GET | `/` | name, version, links to `/docs` and `/health` |
| GET | `/health` | `status`, `model_loaded`, `model`, `model_version`, `uptime_s` |
| POST | `/predict` | classify one URL. Optional query `?model_only=true` skips the trusted list |
| POST | `/predict/batch` | classify 1–100 URLs (same response shape per URL) |
| GET | `/model-info` | model, parameters, threshold, 43 features, library versions, val/test/OpenPhish/real-world metrics |
| GET | `/docs` | Swagger UI (interactive), `/openapi.json` |

### API contract

**Request** `POST /predict`
```json
{"url": "http://185.234.72.19/paypal.com/webscr/login.php?cmd=_login-run"}
```
**Response** `200` (real output of the local server)
```json
{
  "url": "http://185.234.72.19/paypal.com/webscr/login.php?cmd=_login-run",
  "normalized_url": "185.234.72.19/paypal.com/webscr/login.php?cmd=_login-run",
  "verdict": "malicious",
  "is_malicious": true,
  "probability": 0.952641,
  "threshold": 0.8,
  "decided_by": "model",
  "reasons": ["Several login / verification words",
              "Brand name appears outside the real domain",
              "Host is an IP address, not a domain name"],
  "latency_ms": 11.19,
  "model_version": "voting_tuned_noiseclean@2026-11-24"
}
```
* `verdict` is `"malicious"` or `"safe"`.
* `decided_by` is `"model"` or `"trusted_list"`.
* `reasons` holds up to 3 entries, and is empty for safe verdicts.
* `probability` is always the model's P(malicious), even when the trusted list decides.

**Request** `POST /predict/batch` → **Response** `{"results": [ <same object per URL> ], "count": 2, "latency_ms": 10.27}`
```json
{"urls": ["https://github.com/login", "https://secure-paypal-verify.pages.dev/login"]}
```
For these two URLs, `github.com/login` comes back `safe` (decided_by `trusted_list`, model
probability 0.824). `secure-paypal-verify.pages.dev/login` comes back `malicious` (probability
0.990).

### Examples in three clients

**curl** (Git Bash / Linux / macOS)
```bash
curl -s -X POST "$API/predict" -H "Content-Type: application/json" -d '{"url":"https://www.google.com/search?q=python"}'
curl -s -X POST "$API/predict/batch" -H "Content-Type: application/json" -d '{"urls":["https://github.com/login","http://192.168.1.5/a.exe"]}'
curl -s "$API/health"
```
**PowerShell**
```powershell
Invoke-RestMethod -Method Post -Uri "$API/predict" -ContentType "application/json" -Body '{"url":"https://www.google.com/search?q=python"}'
```
```powershell
Invoke-RestMethod -Method Post -Uri "$API/predict/batch?model_only=true" -ContentType "application/json" -Body '{"urls":["https://github.com/login","http://192.168.1.5/a.exe"]}'
```
**Python**
```python
import httpx
API = "https://<your-service>.onrender.com"
r = httpx.post(f"{API}/predict", json={"url": "https://www.google.com/search?q=python"}, timeout=60)
print(r.json()["verdict"], r.json()["probability"], r.json()["decided_by"])
```

### Error codes

| status | body | when |
|---|---|---|
| 200 | prediction | valid request |
| 422 | `{"error": "invalid_request", "detail": [{"field": "url", "message": "url is empty"}]}` | empty or whitespace URL, URL > 2000 characters, no parseable host (e.g. `justtext`, `http://`, control characters), missing field, batch of 0 or > 100 URLs |
| 500 | `{"error": "internal_error"}` | unexpected server error. The stack trace goes only to the server log, never to the client |

## 3. Configuration (environment variables)

| variable | default | meaning |
|---|---|---|
| `MODEL_DIR` | `./models` (`/app/models` in Docker) | folder with `best_model.joblib`, `feature_extractor.joblib`, `model_metadata.json` |
| `TRUSTED_LIST_ENABLED` | `true` | `false` disables the trusted-domain list for every request |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` |
| `CACHE_SIZE` | `10000` | LRU cache entries (normalised URL → model output) |
| `PORT` | `10000` (Render sets it) | port used by the start command |

## 4. Environment and dependencies

* **Python 3.14.3**: the same version the model was trained with (`model_metadata.json`).
  The image is `python:3.14-slim`.
* **`requirements-api.txt`**, exact versions:
  * fastapi 0.165.0, uvicorn 0.54.0, pydantic 2.14.4
  * scikit-learn 1.9.1, numpy 2.5.5, pandas 3.1.1, scipy 1.18.1
  * tldextract 5.4.0, joblib 1.6.0, threadpoolctl 3.8.0
  * **xgboost-cpu 3.4.1** (the official CPU-only build of xgboost; same `import xgboost`, without
    the CUDA libraries) and **lightgbm 4.7.0**. Both are needed because the ensemble contains
    XGBoost and LightGBM members.
* **System package:** `libgomp1`, the OpenMP runtime LightGBM needs on slim images.
* **Wheel check:** all pinned versions resolve to Linux wheels for Python 3.14
  (`pip install --dry-run --platform manylinux… --python-version 3.14 -r requirements-api.txt`).
* **Development environment:** `requirements.txt` (direct pins) and `requirements-lock.txt` (full
  freeze).

## 5. Run locally

```powershell
.\.venv\Scripts\python.exe -m pip install fastapi==0.165.0 uvicorn==0.54.0
```
```powershell
.\.venv\Scripts\python.exe -m uvicorn api.main:app --port 8000
```
Then open http://127.0.0.1:8000/docs.

**Docker** (if Docker Desktop is running):
```powershell
docker build -t malicious-url-api .
```
```powershell
docker run --rm -p 10000:10000 malicious-url-api
```
The Docker engine was not running on the development laptop, and installing or starting it would
have meant a large download over a slow link. The image is therefore built in the cloud by Render
from the same `Dockerfile`. Locally, the identical app was tested with uvicorn.

**Dockerfile summary:**
* `python:3.14-slim` base;
* `libgomp1` installed;
* dependencies installed first, as a cached layer;
* only `src/`, `api/`, the 3 model files and `feature_list.json` copied in (`.dockerignore`
  excludes data, notebooks, reports, `.venv`, `models/cache`, `.git`);
* runs as a non-root user (`appuser`, uid 10001);
* `HEALTHCHECK` on `/health`;
* shell-form `CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-10000}`.

## 6. Deploy on Render (Blueprint)

`render.yaml` defines one **web service**:
* `runtime: docker`, `plan: free`, `region: singapore`;
* `healthCheckPath: /health`, `autoDeploy: true` (every push to `main` redeploys);
* environment variables `TRUSTED_LIST_ENABLED=true`, `LOG_LEVEL=INFO`, `MODEL_DIR=/app/models`.

Steps:
1. Sign in to https://render.com with GitHub.
2. **New + → Blueprint →** connect `deva104/MaliciousURL` → **Apply**.
3. Wait until the status turns **Live**. The logs show `model … loaded` and `Uvicorn running on
   http://0.0.0.0:10000`.
4. The URL is shown under the service name (`https://<name>.onrender.com`).

**Cold start.** Free Render services sleep after about 15 minutes without traffic, and the first
request then wakes the container. **Open `/health` about 2 minutes before the demo.**

## 7. Trusted-domain safety net

**Why.** In Step 2 the model, at its strict threshold 0.80, still flagged 5 of 86 popular
legitimate URLs (the GitHub, PayPal and Netflix login pages, a Google Form and a Google Slides
link). A browser extension that blocks paypal.com/signin would be uninstalled immediately.

**How.**
1. `src/trusted_domains.py` holds 175 curated domains: global platforms; Indian banks
   (onlinesbi.sbi, hdfcbank.com, icicibank.com, …), government (uidai.gov.in, incometax.gov.in,
   irctc.co.in, …) and education (mitaoe.ac.in, nptel.ac.in, …); shopping and payments.
2. They are matched on the **exact registered domain** with the same tldextract logic as the
   features, so `paypal.com.secure-login.tk` has the registered domain `secure-login.tk` and is
   not trusted.
3. **User-content hosts are never trusted**, even when their registered domain is on the list:
   sites.google.com, docs.google.com/forms, drive.google.com, storage.googleapis.com, Firebase,
   *.github.io, githubusercontent.com, gist.github.com, *.vercel.app, *.netlify.app, *.pages.dev,
   *.blogspot.com, *.weebly.com, *.wixsite.com, 000webhostapp.com, forms.office.com,
   sharepoint.com, OneDrive, IPFS gateways, backblazeb2.com and other free hosts seen among the
   OpenPhish misses. Open redirects (google.com/url, youtube.com/redirect, l.facebook.com, …) and
   GitHub release downloads are not trusted either.
4. `?model_only=true` or `TRUSTED_LIST_ENABLED=false` skips the list. Every response reports
   `decided_by`. The notebook metrics are model-only.

**Measured impact** (`scripts/trusted_list_impact.py` → `reports/metrics/trusted_list_impact.json`):

| set | list OFF (model only) | list ON | decided by the list |
|---|---|---|---|
| 86 real-world benign URLs | **5 false positives** | **1 false positive** (the Google Form, on purpose) | 81 |
| 298 OpenPhish phishing URLs | recall **79.19%** | recall **79.19%** | **0** |

The list fixed the GitHub, PayPal and Netflix logins and the Google Slides link. **No phishing URL
was let through by the list.**

## 8. Testing results

* **pytest:** 92 passed. That covers 54 feature tests, 16 tests for `src/predict.py`, and 22 API
  tests:
  * `/health`; Google variants;
  * an IP-host phishing URL is malicious;
  * sites.google.com, github.io, Google Forms and google.com/url bypass the list;
  * `model_only`; 422 for empty, too-long and garbage input and for a 101-URL batch;
  * batch == single; the CORS header for `chrome-extension://abc`; local latency.
* **Local load test** (`scripts/load_test.py`, 1,000 POST `/predict` at concurrency 20, one
  uvicorn process on the development laptop; about 50% repeated URLs, which hit the cache, and 50%
  unique URLs):

| requests | errors | requests/s | p50 | p95 | p99 | max |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 0 | **101.5** | 199.8 ms | 273.3 ms | 326.8 ms | 419.7 ms |

  A single prediction takes about 10–14 ms. At concurrency 20 the latency is dominated by queueing
  in one process (20 ÷ ~100 requests/s ≈ 200 ms).
* **Server memory** (RSS of the uvicorn process): **281 MB** after start-up and warm-up, **288 MB**
  after the 1,000-request test. That fits Render's 512 MB free tier with ~220 MB to spare.
* **Live test** (`scripts/live_test.py` → `reports/metrics/live_api_test.json`, 2026-11-24 18:24 UTC,
  client in India, service in Render Singapore, free plan):

| check | result |
|---|---|
| `/health`, `/`, `/docs`, `/openapi.json`, `/model-info` | all **200**; model = Soft Voting, threshold 0.8, 43 features |
| 5 safe URLs (Google search, GitHub repo, onlinesbi.sbi, mitaoe.ac.in, Wikipedia) | **5/5 safe** (trusted list; the model alone also gives only 0.05–0.31) |
| 5 OpenPhish URLs | **4/5 malicious**: *.github.io (0.98) and *.netlify.app (1.00) correctly bypassed the trusted list; the miss scored 0.76, just below 0.80 |
| `/predict/batch` (10 URLs) | 200, count 10 |
| invalid input (`justtext`) | **422** |
| CORS preflight from `chrome-extension://abc` | `access-control-allow-origin: *` |
| warm latency | `/health` round trip median **89 ms**; `/predict` round trip median **103 ms**, of which **14.2 ms** is the server-side prediction (same as locally); the rest is network |
| cold start | **not observed in this run**: the instance had just been deployed and was awake (uptime ~150 s; first `/health` 198 ms). Render's free instances sleep after ~15 min idle, and the first request after sleep takes noticeably longer. **Open `/health` ~2 min before the demo** |
| load test (200 requests, concurrency 5) | **0 errors**, 8.1 requests/s, p50 610 ms, p95 907 ms, p99 1,221 ms |

  The live throughput (8 requests/s) is far below the laptop's (101 requests/s). The free instance
  has only a fraction of one CPU core, so concurrent requests queue, while a single prediction
  still takes ~14 ms of compute. The Chrome extension sends one URL per page load, which this
  handles easily. For more users, see section 9.

## 9. Scalability

* **Stateless.** Each request depends only on the URL and the read-only model files: no database,
  sessions or user data. Any number of identical containers can run behind a load balancer
  (Render instances, AWS ALB + ECS/Fargate, GCP Cloud Run, Azure Container Apps) without
  coordination.
* **Vertical vs horizontal.**
  * One process serves ~100 predictions/s on one core.
  * `uvicorn --workers N` multiplies that on a bigger machine. Each worker loads its own copy of
    the model (~280 MB RSS), so the 512 MB free tier allows 1 worker; a 2 GB instance can run ~6.
  * Horizontal scaling (more instances) is the cleaner option, and the image is the same.
* **Caching.** A 10k-entry LRU cache on the normalised URL makes repeat visits (the same sites
  every day) cost microseconds; the cache-hit latency in the examples is 0.04 ms. A shared
  Redis cache would serve all instances.
* **Batch endpoint.** Up to 100 URLs per request share one vectorised feature + prediction pass.
  That is efficient for checking all links on a page at once.
* **Model size vs RAM vs cold start.**
  * The 13.3 MB model loads in 0.17 s, and the process uses ~280 MB in total, mostly numpy,
    pandas, scikit-learn, XGBoost and LightGBM.
  * The full-depth Random Forest (388 MB on disk, 2+ GB in RAM) would not fit the free tier and
    would make cold starts much slower. That is why Step 2 enforced the 25 MB / 20 ms limits.
* **Rate limiting (future work).** Add a per-IP limit (e.g. `slowapi` or the API gateway) and an
  API key before opening the API to many users. The Chrome extension can also check its own local
  cache before calling the API.
* **Portability.** The same Docker image runs unchanged on AWS (App Runner / ECS), GCP
  (Cloud Run) or Azure (Container Apps). Only the start command's `PORT` and the health-check path
  need configuring.

## 10. Security and privacy

* **CORS:** `allow_origins=["*"]` with `allow_credentials=False`. This is safe here because the API
  is **public, read-only and stateless**: no cookies, no authentication, no user data, nothing to
  steal or modify from another origin. The extension calls it from `chrome-extension://<id>`.
* **Privacy:** URLs are **never logged or stored**. Logs contain only the verdict, `decided_by`,
  latency and batch counts. The LRU cache lives only in memory and is lost on restart.
* **Input validation:** length limit, host check and batch limit (422). Errors never expose stack
  traces.
* **Runtime:** the container runs as a non-root user, has only the needed files, and uses pinned
  dependencies.

## 11. Troubleshooting

| symptom | cause / fix |
|---|---|
| first request takes 30–60 s or times out | free instance waking from sleep. Retry, and open `/health` 2 min before demos |
| build fails at `pip install` | a version without a Python 3.14 Linux wheel. All pins were checked with a pip dry-run for manylinux / Python 3.14 |
| `OSError: libgomp.so.1` | LightGBM needs `libgomp1`, which the Dockerfile installs |
| `ModuleNotFoundError: src` when loading the model | the model pickles reference `src.modeling` and `src.features`; run from the repo root (the Docker `WORKDIR` is `/app`) |
| `RuntimeError: feature extractor and model metadata disagree` | the model and extractor come from different runs. Re-run notebook 02 |
| 422 for a real URL | the URL has no parseable host (e.g. a missing domain). The response `detail` says why |
| `/health` shows `loading` | the model is still loading at start-up; wait a few seconds |

## 12. Limitations

* URL-only features miss phishing on brand-new, plain-looking domains (22% recall on never-seen
  OpenPhish domains in Step 2).
* The strict threshold (FPR ≤ 1%) halves recall; this is a deliberate trade-off.
* The free tier sleeps (cold start) and has one small CPU: about 100 predictions/s at best.
* The trusted list needs maintenance, and a compromised trusted site would be missed. The list
  deliberately excludes all user-content hosts.
