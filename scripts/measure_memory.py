"""Measure process memory before/after loading the deployed model (fresh process).

Usage: python scripts/measure_memory.py models/best_model.joblib
Prints one JSON line. Libraries are imported BEFORE the baseline so that the
numbers isolate the cost of the extractor and the model themselves.
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import lightgbm  # noqa: E402,F401
import numpy  # noqa: E402,F401
import pandas  # noqa: E402,F401
import psutil  # noqa: E402
import sklearn.ensemble  # noqa: E402,F401
import xgboost  # noqa: E402,F401

from src import features, modeling  # noqa: E402,F401


def rss_mb() -> float:
    return round(psutil.Process().memory_info().rss / 1e6, 1)


def main() -> None:
    before = rss_mb()
    fx = joblib.load(ROOT / "models" / "feature_extractor.joblib")
    after_fx = rss_mb()
    t = time.perf_counter()
    model = joblib.load(sys.argv[1])
    load_s = time.perf_counter() - t
    after_model = rss_mb()
    model.predict_proba(fx.transform_one("https://www.google.com/search?q=x"))
    print(json.dumps({"rss_before_mb": before, "rss_after_extractor_mb": after_fx,
                      "rss_after_model_mb": after_model, "rss_after_first_prediction_mb": rss_mb(),
                      "load_time_s": round(load_s, 3)}))


if __name__ == "__main__":
    main()
