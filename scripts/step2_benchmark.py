"""Step 2 pre-flight: machine info + RandomForest benchmark + time plan.

Writes reports/metrics/benchmark.json (shown again in notebook 02).
Run:  .venv\\Scripts\\python.exe scripts\\step2_benchmark.py
"""
from __future__ import annotations

import json
import os
import pickle
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import psutil  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402

from src import data as D  # noqa: E402
from src.config import PROCESSED, RANDOM_STATE  # noqa: E402

OUT = ROOT / "reports" / "metrics" / "benchmark.json"


def main() -> None:
    feats = json.loads((PROCESSED / "feature_list.json").read_text())["features"]
    tr = pd.read_parquet(PROCESSED / "train.parquet", columns=feats + ["label", "registered_domain"])
    vm = psutil.virtual_memory()
    info = {
        "cpu": platform.processor(),
        "logical_cores": os.cpu_count(),
        "physical_cores": psutil.cpu_count(logical=False),
        "ram_total_gb": round(vm.total / 1e9, 1),
        "ram_available_gb": round(vm.available / 1e9, 1),
        "train_rows": len(tr),
    }
    print(info)

    idx = D.grouped_sample(tr, 100_000, random_state=RANDOM_STATE)
    X, y = tr.iloc[idx][feats], tr["label"].to_numpy()[idx]
    print(f"benchmark sample: {len(idx):,} rows, malicious share {y.mean():.3f} (train {tr.label.mean():.3f})")

    t = time.perf_counter()
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE).fit(X, y)
    t_par = time.perf_counter() - t
    size_mem_mb = len(pickle.dumps(rf)) / 1e6
    nodes = int(sum(e.tree_.node_count for e in rf.estimators_))
    t = time.perf_counter()
    RandomForestClassifier(n_estimators=24, n_jobs=1, random_state=RANDOM_STATE).fit(X, y)
    t_tree_1core = (time.perf_counter() - t) / 24
    print(f"RF 200 trees, n_jobs=-1, 100k rows: {t_par:.1f}s | single-core per tree {t_tree_1core:.2f}s | "
          f"in-memory ~{size_mem_mb:.0f} MB | {nodes:,} nodes")

    n_full = len(tr)
    scale = n_full / len(idx) * np.log(n_full) / np.log(len(idx))     # ~ n log n per tree
    rf_full = t_par * scale
    search_fit = t_tree_1core * 200 * 1.0           # one 200-tree fit on ~100k rows (2/3 of 150k)
    plan = {
        "1 baselines (13 models, RF/ET/Bag full depth, stacking 3 folds)": rf_full * 10 + 240,
        "1b class-weight (RF + LR balanced)": rf_full + 30,
        "2 RF search 25 iters x 3 folds on 150k (24 workers)": 75 * search_fit * 1.3 / 24,
        "2 refit best RF on full train + size/F1 trade-off (~6 RFs)": rf_full * 7,
        "2 booster search 15 x 3 + refit": 180,
        "2 tuned Voting + Stacking": rf_full * 3 + 150,
        "2 label-noise retrain": rf_full,
        "3-5 threshold, test, OpenPhish, importance, latency": 240,
    }
    total = sum(plan.values())
    print(f"\nextrapolated full-train RF (200 trees, n_jobs=-1): ~{rf_full:.0f}s")
    print(f"estimated full-train RF size in memory: ~{size_mem_mb * n_full / len(idx):.0f} MB")
    print("\nTime plan (estimates):")
    for k, v in plan.items():
        print(f"  {k:<62} {v/60:6.1f} min")
    print(f"  {'TOTAL':<62} {total/60:6.1f} min")
    info.update({
        "bench_rows": int(len(idx)), "rf200_fit_s_njobs_all": round(t_par, 2),
        "rf_tree_fit_s_single_core": round(t_tree_1core, 3), "rf200_in_memory_mb": round(size_mem_mb, 1),
        "rf200_nodes": nodes, "extrapolated_full_rf200_fit_s": round(rf_full, 1),
        "estimated_full_rf200_memory_mb": round(size_mem_mb * n_full / len(idx)),
        "plan_minutes": {k: round(v / 60, 1) for k, v in plan.items()}, "plan_total_minutes": round(total / 60, 1),
    })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(info, indent=2))
    print("saved", OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
