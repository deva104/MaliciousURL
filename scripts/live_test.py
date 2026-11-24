"""End-to-end test of the DEPLOYED API.

Usage: python scripts/live_test.py --base-url https://<service>.onrender.com
Writes reports/metrics/live_api_test.json (+ load test with concurrency 5).
"""
import argparse
import asyncio
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SAFE = ["https://www.google.com/search?q=machine+learning", "https://github.com/scikit-learn/scikit-learn",
        "https://www.onlinesbi.sbi/", "https://mitaoe.ac.in/", "https://en.wikipedia.org/wiki/Random_forest"]


def timed(client, method, path, **kw):
    t = time.perf_counter()
    r = client.request(method, path, **kw)
    return r, round((time.perf_counter() - t) * 1000, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--load-n", type=int, default=200)
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    ops = [u.strip() for u in sorted((ROOT / "data/external").glob("openphish_feed_*.txt"))[-1]
           .read_text(encoding="utf-8").splitlines() if u.strip()][:5]
    res = {"base_url": base, "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with httpx.Client(base_url=base, timeout=180) as c:
        r, ms = timed(c, "GET", "/health")
        res["first_request_health"] = {"status": r.status_code, "ms": ms, "body": r.json() if r.status_code == 200 else r.text[:200],
                                       "note": "includes cold start if the free instance was asleep"}
        warm = [timed(c, "GET", "/health")[1] for _ in range(10)]
        res["warm_health_ms"] = {"median": statistics.median(warm), "max": max(warm)}
        for path in ["/", "/docs", "/openapi.json"]:
            r, ms = timed(c, "GET", path)
            res[f"GET {path}"] = {"status": r.status_code, "ms": ms}
        r, ms = timed(c, "GET", "/model-info")
        mi = r.json()
        res["GET /model-info"] = {"status": r.status_code, "ms": ms, "model": mi.get("model_name"),
                                  "threshold": mi.get("threshold"), "n_features": mi.get("n_features")}
        preds = []
        for kind, urls in [("safe", SAFE), ("openphish", ops)]:
            for u in urls:
                r, ms = timed(c, "POST", "/predict", json={"url": u})
                b = r.json()
                preds.append({"kind": kind, "url": u, "status": r.status_code, "verdict": b.get("verdict"),
                              "probability": b.get("probability"), "decided_by": b.get("decided_by"),
                              "server_latency_ms": b.get("latency_ms"), "round_trip_ms": ms})
        res["predict"] = preds
        res["predict_summary"] = {
            "safe_correct": sum(p["verdict"] == "safe" for p in preds if p["kind"] == "safe"),
            "openphish_detected": sum(p["verdict"] == "malicious" for p in preds if p["kind"] == "openphish"),
            "median_round_trip_ms": statistics.median(p["round_trip_ms"] for p in preds),
            "median_server_latency_ms": statistics.median(p["server_latency_ms"] for p in preds)}
        r, ms = timed(c, "POST", "/predict/batch", json={"urls": SAFE + ops})
        res["POST /predict/batch"] = {"status": r.status_code, "round_trip_ms": ms, "count": r.json().get("count"),
                                      "server_latency_ms": r.json().get("latency_ms")}
        r, _ = timed(c, "POST", "/predict", json={"url": "justtext"})
        res["invalid_input_status"] = r.status_code
        r = c.options("/predict", headers={"Origin": "chrome-extension://abc", "Access-Control-Request-Method": "POST"})
        res["cors_allow_origin"] = r.headers.get("access-control-allow-origin")
    from scripts.load_test import run as load_run
    res["load_test_concurrency_5"] = asyncio.run(load_run(base, a.load_n, 5, 120))
    out = ROOT / "reports/metrics/live_api_test.json"
    out.write_text(json.dumps(res, indent=2))
    print(json.dumps({k: v for k, v in res.items() if k != "predict"}, indent=2))
    print("saved", out.relative_to(ROOT))


if __name__ == "__main__":
    main()
