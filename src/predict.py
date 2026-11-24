"""Inference API used by the FastAPI service (Step 3) and the Chrome extension backend.

    from src.predict import predict_url, predict_batch
    predict_url("https://www.google.com/search?q=x")
    -> {"url": ..., "normalized_url": "google.com/search?q=x", "probability": 0.01,
        "is_malicious": False, "threshold": 0.6, "reasons": []}

All feature code comes from src/features.py through the saved extractor
(models/feature_extractor.joblib); nothing is re-implemented here.
"""
from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd

from .config import MODELS
from .features import normalize_url, parse_url

# (feature used for ordering, condition on the feature row, message)
# Conditions only use the 43 model features; messages are shown to end users.
REASON_RULES = [
    ("has_ip_host", lambda r: r["has_ip_host"] == 1, lambda r, tld: "Host is an IP address, not a domain name"),
    ("brand_in_non_registered_part", lambda r: r["brand_in_non_registered_part"] == 1,
     lambda r, tld: "Brand name appears outside the real domain"),
    ("tld_malicious_rate", lambda r: r["has_ip_host"] == 0 and (r["tld_malicious_rate"] >= 0.8 or r["suspicious_tld"] == 1),
     lambda r, tld: f"Top-level domain .{tld} is frequently used for malicious sites"),
    ("url_len", lambda r: r["url_len"] > 100, lambda r, tld: "Very long URL"),
    ("host_num_dots", lambda r: r["host_num_dots"] >= 4, lambda r, tld: "Many subdomains"),
    ("has_punycode", lambda r: r["has_punycode"] == 1,
     lambda r, tld: "Internationalised (punycode) domain, possible look-alike"),
    ("has_at_symbol", lambda r: r["has_at_symbol"] == 1, lambda r, tld: "'@' symbol can hide the real destination"),
    ("is_shortener", lambda r: r["is_shortener"] == 1, lambda r, tld: "URL shortener hides the real destination"),
    ("risky_file_extension", lambda r: r["risky_file_extension"] == 1,
     lambda r, tld: "Direct download of an executable or archive file"),
    ("host_entropy", lambda r: r["has_ip_host"] == 0 and (r["host_entropy"] >= 4.0 or r["host_num_digits"] >= 6),
     lambda r, tld: "Random-looking host name"),
    ("tld_in_subdomain", lambda r: r["tld_in_subdomain"] == 1,
     lambda r, tld: "Domain-like text hidden in the subdomain (e.g. paypal.com.evil.tk)"),
    ("has_port", lambda r: r["has_port"] == 1, lambda r, tld: "Non-standard port number"),
    ("embedded_url", lambda r: r["embedded_url"] == 1, lambda r, tld: "Contains another URL (redirect)"),
    ("suspicious_keyword_count", lambda r: r["suspicious_keyword_count"] >= 2,
     lambda r, tld: "Several login / verification words"),
]


@lru_cache(maxsize=1)
def load_artifacts(models_dir: str | Path | None = None) -> tuple:
    """(extractor, model, metadata), loaded once per process and checked for consistency.

    Directory: the argument, else the MODEL_DIR environment variable, else ./models.
    """
    models_dir = Path(models_dir or os.getenv("MODEL_DIR") or MODELS)
    meta = json.loads((models_dir / "model_metadata.json").read_text())
    fx = joblib.load(models_dir / "feature_extractor.joblib")
    model = joblib.load(models_dir / "best_model.joblib")
    sha = hashlib.sha256(json.dumps(fx.feature_names).encode()).hexdigest()
    if fx.feature_names != meta["feature_list"] or sha != meta["feature_list_sha256"]:
        raise RuntimeError("feature extractor and model metadata disagree on the feature list")
    return fx, model, meta


def _rank(meta: dict) -> dict[str, int]:
    order = meta.get("feature_importance_order") or meta["feature_list"]
    return {f: i for i, f in enumerate(order)}


def explain(row: pd.Series, url: str, meta: dict, k: int = 3) -> list[str]:
    """Up to k triggered reasons, most globally important feature first."""
    tld = parse_url(url).tld.strip("<>")
    rank = _rank(meta)
    hits = [(rank.get(f, 999), msg(row, tld)) for f, cond, msg in REASON_RULES if cond(row)]
    return [m for _, m in sorted(hits)[:k]]


def _result(url: str, proba: float, row: pd.Series, meta: dict) -> dict:
    thr = float(meta["threshold"])
    return {"url": url, "normalized_url": normalize_url(url), "probability": round(float(proba), 6),
            "is_malicious": bool(proba >= thr), "threshold": thr, "reasons": explain(row, url, meta)}


def predict_url(url: str) -> dict:
    fx, model, meta = load_artifacts()
    url = "" if url is None else str(url)
    X = fx.transform_one(url)
    proba = float(model.predict_proba(X)[0, 1])
    return _result(url, proba, X.iloc[0], meta)


def predict_batch(urls: Iterable[str]) -> list[dict]:
    fx, model, meta = load_artifacts()
    urls = ["" if u is None else str(u) for u in urls]
    if not urls:
        return []
    X = fx.transform(urls).reset_index(drop=True)
    proba = model.predict_proba(X)[:, 1]
    return [_result(u, p, X.iloc[i], meta) for i, (u, p) in enumerate(zip(urls, np.asarray(proba)))]
