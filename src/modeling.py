"""Step 2 helpers: model zoo, training cache, metrics, latency/size, thresholds.

Everything expensive is cached in models/cache/ so that re-executing notebook 02
reuses the REAL training run (models, timings, predictions) instead of retraining:

    models/cache/<name>.joblib            fitted model (joblib compress=3 -> its size)
    models/cache/<name>.json              fit time, size, latency, throughput, extras
    models/cache/<name>__<set>.npy        P(malicious) on an evaluation set

Big forests (full-depth RF/ExtraTrees take 2-5 GB of RAM on 591k rows) are
trained one at a time, evaluated while in memory, saved, then freed.
"""
from __future__ import annotations

import gc
import json
import os
import time
from pathlib import Path
from typing import Callable

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score, f1_score,
                             precision_score, recall_score, roc_auc_score)

from .config import EXTERNAL, MODELS, PROCESSED, RANDOM_STATE, ROOT
from .features import parse_url

CACHE = MODELS / "cache"
METRICS_DIR = ROOT / "reports" / "metrics"
FAMILY_ORDER = ["single", "bagging", "boosting", "combination"]


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #
def feature_list() -> list[str]:
    return json.loads((PROCESSED / "feature_list.json").read_text())["features"]


def load_split(name: str, feats: list[str]) -> pd.DataFrame:
    cols = feats + ["label", "type", "source", "registered_domain", "url_original", "url_normalized"]
    return pd.read_parquet(PROCESSED / f"{name}.parquet", columns=cols)


def load_openphish(path: Path | None = None) -> pd.DataFrame:
    """OpenPhish snapshot -> normalised, de-duplicated frame (all label 1)."""
    if path is None:
        path = sorted(EXTERNAL.glob("openphish_feed_*.txt"))[-1]
    raw = [u.strip() for u in Path(path).read_text(encoding="utf-8").splitlines() if u.strip()]
    df = pd.DataFrame({"url_original": raw})
    parts = [parse_url(u) for u in df["url_original"]]
    df["url_normalized"] = [p.normalized for p in parts]
    df["host"] = [p.host for p in parts]
    df["registered_domain"] = [p.group_key for p in parts]
    n_raw = len(df)
    df = df.drop_duplicates("url_normalized").reset_index(drop=True)
    df["label"] = 1
    df.attrs.update({"n_raw": n_raw, "n_dedup": len(df), "file": Path(path).name})
    return df


def load_realworld() -> pd.DataFrame:
    df = pd.read_csv(EXTERNAL / "realworld_benign_urls.csv")
    df["label"] = 0
    return df


# --------------------------------------------------------------------------- #
# Metrics and thresholds
# --------------------------------------------------------------------------- #
def binary_metrics(y: np.ndarray, proba: np.ndarray, thr: float = 0.5) -> dict:
    y = np.asarray(y).astype(int)
    pred = (proba >= thr).astype(int)
    neg = y == 0
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "roc_auc": roc_auc_score(y, proba) if len(np.unique(y)) > 1 else np.nan,
        "pr_auc": average_precision_score(y, proba) if len(np.unique(y)) > 1 else np.nan,
        "fpr": float(pred[neg].mean()) if neg.any() else np.nan,
    }


def threshold_table(y: np.ndarray, proba: np.ndarray, grid: np.ndarray | None = None) -> pd.DataFrame:
    """precision / recall / F1 / FPR for a grid of thresholds (vectorised)."""
    if grid is None:
        grid = np.round(np.arange(0.05, 0.951, 0.01), 2)
    y = np.asarray(y).astype(bool)
    pos, neg = y.sum(), (~y).sum()
    order = np.argsort(proba)
    p_sorted, y_sorted = proba[order], y[order]
    # number of positives / negatives with proba >= t
    cum_pos = np.concatenate([np.cumsum(y_sorted[::-1])[::-1], [0]])
    cum_neg = np.concatenate([np.cumsum(~y_sorted[::-1])[::-1], [0]])
    idx = np.searchsorted(p_sorted, grid, side="left")
    tp, fp = cum_pos[idx], cum_neg[idx]
    precision = np.divide(tp, tp + fp, out=np.zeros(len(grid)), where=(tp + fp) > 0)
    recall = tp / pos
    f1 = np.divide(2 * precision * recall, precision + recall, out=np.zeros(len(grid)),
                   where=(precision + recall) > 0)
    return pd.DataFrame({"threshold": grid, "precision": precision, "recall": recall,
                         "f1": f1, "fpr": fp / neg})


def pick_threshold(y: np.ndarray, proba: np.ndarray, max_fpr: float = 0.01) -> tuple[float, pd.DataFrame]:
    """Threshold with the highest F1 among those with FPR <= max_fpr."""
    tab = threshold_table(y, proba)
    ok = tab[tab["fpr"] <= max_fpr]
    best = ok.loc[ok["f1"].idxmax()] if len(ok) else tab.loc[tab["fpr"].idxmin()]
    return float(best["threshold"]), tab


# --------------------------------------------------------------------------- #
# Deployment helpers
# --------------------------------------------------------------------------- #
def set_n_jobs(est, n: int = 1):
    """Recursively set n_jobs on a (fitted) estimator, incl. fitted ensemble members."""
    if hasattr(est, "steps"):                                   # Pipeline
        for _, step in est.steps:
            set_n_jobs(step, n)
    members = getattr(est, "members", None)                     # SoftVotingPrefit
    if members:
        for m in members:
            set_n_jobs(m, n)
    if est.__class__.__name__ in ("StackingClassifier", "VotingClassifier"):
        for m in getattr(est, "estimators_", []):
            set_n_jobs(m, n)
        if hasattr(est, "final_estimator_"):
            set_n_jobs(est.final_estimator_, n)
    try:
        if "n_jobs" in est.get_params(deep=False):
            est.set_params(n_jobs=n)
    except Exception:
        pass
    return est


def measure_latency(model, extractor, urls: list[str], n: int = 200, warmup: int = 5) -> dict:
    """Single-URL latency INCLUDING feature extraction, 1 thread (like a small server)."""
    from threadpoolctl import threadpool_limits

    set_n_jobs(model, 1)
    times = []
    with threadpool_limits(1):
        for u in urls[:warmup]:
            model.predict_proba(extractor.transform_one(u))
        for u in urls[:n]:
            t = time.perf_counter()
            model.predict_proba(extractor.transform_one(u))
            times.append((time.perf_counter() - t) * 1000)
    return {"latency_ms_median": float(np.median(times)), "latency_ms_p95": float(np.percentile(times, 95))}


def measure_throughput(model, extractor, urls: list[str]) -> dict:
    """Batch throughput (feature extraction + prediction), 1 thread."""
    from threadpoolctl import threadpool_limits

    set_n_jobs(model, 1)
    with threadpool_limits(1):
        t = time.perf_counter()
        model.predict_proba(extractor.transform(urls))
        dt = time.perf_counter() - t
    return {"throughput_urls_per_s": len(urls) / dt, "throughput_batch": len(urls)}


from sklearn.base import BaseEstimator, ClassifierMixin  # noqa: E402


class SoftVotingPrefit(ClassifierMixin, BaseEstimator):
    """Soft voting over ALREADY-FITTED members: P = mean of members' P(malicious).

    Mathematically identical to sklearn's VotingClassifier(voting="soft") with
    equal weights, but reuses the cached members instead of refitting them.
    It is a real scikit-learn classifier (tags, get_params), so tools such as
    permutation_importance accept it; `fit` is a no-op because the members are
    already trained.
    """

    def __init__(self, members: list | None = None, names: list[str] | None = None):
        self.members = members
        self.names = names

    @property
    def classes_(self):
        return np.array([0, 1])

    def fit(self, X=None, y=None):
        return self

    def predict_proba(self, X):
        p = np.mean([m.predict_proba(X)[:, 1] for m in self.members], axis=0)
        return np.column_stack([1 - p, p])

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


# --------------------------------------------------------------------------- #
# Model store (cache)
# --------------------------------------------------------------------------- #
class ModelStore:
    """Train-once cache. `ensure()` fits only if <name> is not cached yet."""

    def __init__(self, extractor, latency_urls: list[str], throughput_urls: list[str],
                 cache: Path = CACHE):
        self.cache = Path(cache)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.extractor = extractor
        self.latency_urls = latency_urls
        self.throughput_urls = throughput_urls
        self.eval_sets: dict[str, Callable[[], pd.DataFrame]] = {}

    # ---- paths ---------------------------------------------------------- #
    def _model_path(self, name):
        return self.cache / f"{name}.joblib"

    def _meta_path(self, name):
        return self.cache / f"{name}.json"

    def _proba_path(self, name, key):
        return self.cache / f"{name}__{key}.npy"

    def register_eval_set(self, key: str, X_fn: Callable[[], pd.DataFrame]) -> None:
        self.eval_sets[key] = X_fn

    def has(self, name: str) -> bool:
        return self._meta_path(name).exists() and self._model_path(name).exists()

    def meta(self, name: str) -> dict:
        return json.loads(self._meta_path(name).read_text())

    def load(self, name: str):
        return joblib.load(self._model_path(name))

    def proba(self, name: str, key: str, X: pd.DataFrame | None = None) -> np.ndarray:
        """Cached P(malicious); computed (loading the model) only when missing."""
        p = self._proba_path(name, key)
        if p.exists():
            return np.load(p)
        model = self.load(name)
        X = X if X is not None else self.eval_sets[key]()
        out = model.predict_proba(X)[:, 1].astype(np.float32)
        np.save(p, out)
        del model
        gc.collect()
        return out

    # ---- training ------------------------------------------------------- #
    def ensure(self, name: str, family: str, factory: Callable, X: pd.DataFrame, y: np.ndarray,
               extra: Callable | None = None, note: str = "", fitted=None,
               fit_time_s: float | None = None, post_fit: Callable | None = None) -> dict:
        """Fit (or accept an already-fitted model), evaluate, measure, save, free."""
        if self.has(name):
            return self.meta(name)
        if fitted is None:
            est = factory()
            t = time.perf_counter()
            est.fit(X, y)
            fit_time_s = time.perf_counter() - t
        else:
            est = fitted
        if post_fit is not None:
            post_fit(est)
        set_n_jobs(est, -1)                                        # fast batch evaluation
        meta = {"name": name, "family": family, "fit_time_s": round(float(fit_time_s), 2),
                "train_rows": int(len(X)) if X is not None else None, "note": note,
                "params": _short_params(est)}
        if extra is not None:
            meta.update(extra(est))
        for key, X_fn in self.eval_sets.items():                   # predictions while in memory
            np.save(self._proba_path(name, key), est.predict_proba(X_fn())[:, 1].astype(np.float32))
        meta.update(measure_latency(est, self.extractor, self.latency_urls))
        meta.update(measure_throughput(est, self.extractor, self.throughput_urls))
        set_n_jobs(est, 1)                                         # deploy-style (1 thread)
        joblib.dump(est, self._model_path(name), compress=3)
        meta["size_mb"] = round(os.path.getsize(self._model_path(name)) / 1e6, 3)
        self._meta_path(name).write_text(json.dumps(meta, indent=2, default=str))
        del est
        gc.collect()
        return meta


def _short_params(est) -> str:
    try:
        p = est.get_params(deep=False)
        keep = {k: v for k, v in p.items() if not hasattr(v, "get_params") and k not in ("estimators",)}
        return json.dumps(keep, default=str)[:600]
    except Exception:
        return est.__class__.__name__


def save_metrics_table(df: pd.DataFrame, name: str) -> Path:
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    p = METRICS_DIR / f"{name}.csv"
    df.to_csv(p)
    return p


def rf_size_stats(est) -> dict:
    trees = getattr(est, "estimators_", [])
    if not trees or not hasattr(trees[0], "tree_"):
        return {}
    return {"n_nodes_total": int(sum(t.tree_.node_count for t in trees)),
            "mean_depth": float(np.mean([t.get_depth() for t in trees]))}
