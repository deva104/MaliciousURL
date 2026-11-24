"""Malicious URL Detection API (FastAPI).

Run locally:   uvicorn api.main:app --reload --port 8000
Docs:          http://localhost:8000/docs

All feature and model code is reused from src/ (src/predict.py ->
src/features.py + models/*.joblib); this file only adds HTTP, validation,
caching, the trusted-domain safety net and logging.

Configuration (environment variables):
    MODEL_DIR              folder with best_model.joblib, feature_extractor.joblib,
                           model_metadata.json            (default: ./models)
    TRUSTED_LIST_ENABLED   true/false                     (default: true)
    LOG_LEVEL              DEBUG/INFO/WARNING             (default: INFO)
    CACHE_SIZE             LRU entries                    (default: 10000)
    PORT                   used by the start command      (default: 10000 in Docker)
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src import predict as P
from src.data import host_problem
from src.features import normalize_url, parse_url
from src.trusted_domains import TRUSTED_DOMAINS, check_trusted

API_VERSION = "1.0.0"
MAX_URL_LEN = 2048   # = the Chrome extension's limit (characters, after stripping whitespace)
MAX_BATCH = 100


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


TRUSTED_LIST_ENABLED = _env_bool("TRUSTED_LIST_ENABLED", True)
CACHE_SIZE = int(os.getenv("CACHE_SIZE", "10000"))
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("url_api")


# --------------------------------------------------------------------------- #
# Small thread-safe LRU cache (key = normalised URL -> model result)
# --------------------------------------------------------------------------- #
class LRUCache:
    def __init__(self, maxsize: int):
        self.maxsize, self.data, self.lock = maxsize, OrderedDict(), threading.Lock()
        self.hits = self.misses = 0

    def get(self, key):
        with self.lock:
            if key in self.data:
                self.data.move_to_end(key)
                self.hits += 1
                return self.data[key]
            self.misses += 1
            return None

    def put(self, key, value):
        with self.lock:
            self.data[key] = value
            self.data.move_to_end(key)
            if len(self.data) > self.maxsize:
                self.data.popitem(last=False)


CACHE = LRUCache(CACHE_SIZE)
STATE: dict = {"loaded": False, "started": time.time()}


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
def validate_url(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("url must be a string")
    v = v.strip()
    if not v:
        raise ValueError("url is empty")
    if len(v) > MAX_URL_LEN:
        raise ValueError(f"url is longer than {MAX_URL_LEN} characters")
    problem = host_problem(normalize_url(v))
    if problem:
        raise ValueError(f"url has no parseable host ({problem})")
    return v


class PredictRequest(BaseModel):
    url: str = Field(..., description="The full URL, exactly as the browser shows it.",
                     examples=["https://www.google.com/search?q=python+tutorial"])

    @field_validator("url")
    @classmethod
    def check_url(cls, v: str) -> str:
        return validate_url(v)


class BatchRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=MAX_BATCH,
                            description=f"1 to {MAX_BATCH} URLs.",
                            examples=[["https://github.com/login", "http://185.234.72.19/paypal/webscr.php?cmd=_login"]])

    @field_validator("urls")
    @classmethod
    def _check_all(cls, v: list[str]) -> list[str]:
        return [validate_url(u) for u in v]


class PredictResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "url": "http://185.234.72.19/paypal.com/webscr/login.php?cmd=_login",
        "normalized_url": "185.234.72.19/paypal.com/webscr/login.php?cmd=_login",
        "verdict": "malicious", "is_malicious": True, "probability": 0.97, "threshold": 0.6,
        "decided_by": "model", "reasons": ["Host is an IP address, not a domain name",
                                           "Brand name appears outside the real domain"],
        "latency_ms": 3.1, "model_version": "voting_tuned@2026-11-24"}]})
    url: str
    normalized_url: str
    verdict: Literal["malicious", "safe"]
    is_malicious: bool
    probability: float = Field(..., description="Model P(malicious), 0-1 (also reported when the trusted list decides)")
    threshold: float
    decided_by: Literal["model", "trusted_list"]
    reasons: list[str] = Field(..., description="Up to 3 human-readable risk signals (empty for safe verdicts)")
    latency_ms: float
    model_version: str


class BatchResponse(BaseModel):
    results: list[PredictResponse]
    count: int
    latency_ms: float


# --------------------------------------------------------------------------- #
# Core logic
# --------------------------------------------------------------------------- #
def _meta() -> dict:
    return P.load_artifacts()[2]


def _model_version(meta: dict) -> str:
    return f"{meta['model_key']}@{meta['training_date']}"


def _model_results(urls: list[str]) -> list[dict]:
    """Model output per URL, served from the LRU cache when possible."""
    keys = [normalize_url(u) for u in urls]
    out: list[dict | None] = [CACHE.get(k) for k in keys]
    miss = [i for i, r in enumerate(out) if r is None]
    if miss:
        fresh = P.predict_batch([urls[i] for i in miss]) if len(miss) > 1 else [P.predict_url(urls[miss[0]])]
        for i, r in zip(miss, fresh):
            out[i] = {"probability": r["probability"], "reasons": r["reasons"]}
            CACHE.put(keys[i], out[i])
    return out


def classify(urls: list[str], use_trusted: bool, t0: float) -> list[dict]:
    meta = _meta()
    thr, version = float(meta["threshold"]), _model_version(meta)
    model_out = _model_results(urls)
    results = []
    for url, m in zip(urls, model_out):
        trusted, why = check_trusted(url) if use_trusted else (False, "")
        if trusted:
            malicious, decided_by, reasons = False, "trusted_list", []
        else:
            malicious, decided_by = m["probability"] >= thr, "model"
            reasons = m["reasons"] if malicious else []
        results.append({"url": url, "normalized_url": normalize_url(url),
                        "verdict": "malicious" if malicious else "safe", "is_malicious": bool(malicious),
                        "probability": m["probability"], "threshold": thr, "decided_by": decided_by,
                        "reasons": reasons, "latency_ms": 0.0, "model_version": version})
    elapsed = round((time.perf_counter() - t0) * 1000, 3)
    for r in results:
        r["latency_ms"] = elapsed
    return results


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    t = time.perf_counter()
    fx, model, meta = P.load_artifacts()                   # load ONCE
    P.predict_url("https://www.google.com/search?q=warmup")  # warm-up (imports, caches)
    STATE.update(loaded=True, started=time.time(), load_s=round(time.perf_counter() - t, 3))
    log.info("model %s loaded in %.2fs (threshold %.2f, trusted list %s)", _model_version(meta),
             STATE["load_s"], meta["threshold"], "on" if TRUSTED_LIST_ENABLED else "off")
    yield


DESCRIPTION = """
Detects **malicious URLs** (phishing, malware, defacement) from the URL string alone, with no
page download, using the ensemble trained in Step 2 of the project.

* `POST /predict`: one URL. `POST /predict/batch`: up to 100 URLs.
* `verdict` is `malicious` when the model probability is at or above the tuned `threshold`.
* A curated **trusted-domain list** answers very popular domains (google.com, onlinesbi.sbi, ...)
  as safe. It never covers user-content hosts such as sites.google.com, *.github.io or
  *.vercel.app. Pass `?model_only=true` to skip it. Every response says `decided_by`.
* Privacy: URLs are never logged or stored; the logs contain only verdicts, latency and counts.
"""

app = FastAPI(title="Malicious URL Detection API", version=API_VERSION, description=DESCRIPTION,
              lifespan=lifespan,
              openapi_tags=[{"name": "prediction", "description": "Classify URLs"},
                            {"name": "service", "description": "Health and model information"}])

# Public, read-only, stateless API: no cookies, no auth, no user data -> any origin may call it
# (the Chrome extension calls from chrome-extension://<id>). Credentials are NOT allowed.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    detail = [{"field": ".".join(str(x) for x in e.get("loc", [])[1:]) or "body",
               "message": str(e.get("msg", "")).removeprefix("Value error, ")} for e in exc.errors()]
    log.info("422 on %s (%d problems)", request.url.path, len(detail))
    return JSONResponse(status_code=422, content={"error": "invalid_request", "detail": detail})


@app.exception_handler(Exception)
async def internal_handler(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)   # details only in the server log
    return JSONResponse(status_code=500, content={"error": "internal_error"})


ERR = {422: {"description": "Invalid input", "content": {"application/json": {"example": {
    "error": "invalid_request", "detail": [{"field": "url", "message": "url has no parseable host (empty host)"}]}}}},
       500: {"description": "Unexpected server error", "content": {"application/json": {"example": {"error": "internal_error"}}}}}


@app.get("/", tags=["service"], summary="Service information")
def root():
    return {"name": "Malicious URL Detection API", "version": API_VERSION,
            "docs": "/docs", "health": "/health", "model_info": "/model-info"}


@app.get("/health", tags=["service"], summary="Liveness / readiness check")
def health():
    meta = _meta() if STATE["loaded"] else {}
    return {"status": "ok" if STATE["loaded"] else "loading", "model_loaded": STATE["loaded"],
            "model": meta.get("model_name"), "model_version": _model_version(meta) if meta else None,
            "uptime_s": round(time.time() - STATE["started"], 1)}


@app.post("/predict", response_model=PredictResponse, tags=["prediction"], responses=ERR,
          summary="Classify one URL")
def predict(req: PredictRequest,
            model_only: bool = Query(False, description="Skip the trusted-domain list and use only the model")):
    t0 = time.perf_counter()
    r = classify([req.url], TRUSTED_LIST_ENABLED and not model_only, t0)[0]
    log.info("predict verdict=%s decided_by=%s latency_ms=%.2f", r["verdict"], r["decided_by"], r["latency_ms"])
    return r


@app.post("/predict/batch", response_model=BatchResponse, tags=["prediction"], responses=ERR,
          summary=f"Classify up to {MAX_BATCH} URLs")
def predict_batch(req: BatchRequest,
                  model_only: bool = Query(False, description="Skip the trusted-domain list and use only the model")):
    t0 = time.perf_counter()
    res = classify(req.urls, TRUSTED_LIST_ENABLED and not model_only, t0)
    lat = round((time.perf_counter() - t0) * 1000, 3)
    log.info("batch count=%d malicious=%d latency_ms=%.2f", len(res), sum(r["is_malicious"] for r in res), lat)
    return {"results": res, "count": len(res), "latency_ms": lat}


@app.get("/model-info", tags=["service"], summary="Model, threshold, features and evaluation metrics")
def model_info():
    m = _meta()
    return {"model_name": m["model_name"], "model_key": m["model_key"], "model_class": m["model_class"],
            "model_version": _model_version(m), "parameters": m["parameters"], "threshold": m["threshold"],
            "n_features": len(m["feature_list"]), "features": m["feature_list"],
            "feature_list_sha256": m["feature_list_sha256"], "training_date": m["training_date"],
            "library_versions": m["versions"], "metrics": m["metrics"],
            "label_noise_decision": m["label_noise_decision"], "selection_rule": m.get("selection_rule"),
            "trusted_list": {"enabled": TRUSTED_LIST_ENABLED, "domains": len(TRUSTED_DOMAINS)},
            "cache": {"size": len(CACHE.data), "max": CACHE.maxsize, "hits": CACHE.hits, "misses": CACHE.misses},
            "api_version": API_VERSION}


if __name__ == "__main__":  # python -m api.main
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
