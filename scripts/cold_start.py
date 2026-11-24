"""Measure the Render free-tier cold start (run after >= 16 min with ZERO requests to the API).

Usage: python scripts/cold_start.py --base-url https://malicious-url-api.onrender.com
Times the first GET /health until it answers 200 (retries politely for up to 3 min), then 3 warm
GET /health requests. Writes reports/metrics/cold_start.json.
"""
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--max-wait-s", type=float, default=180)
    ap.add_argument("--min-idle-min", type=float, default=16)
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    last = json.loads((ROOT / "reports/metrics/demo_live_results.json").read_text())["last_request_utc"]
    idle_min = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() / 60
    print(f"idle since our last request ({last}): {idle_min:.1f} min")
    if idle_min < a.min_idle_min:
        raise SystemExit(f"only {idle_min:.1f} min idle; need >= {a.min_idle_min}")
    attempts, t0 = [], time.perf_counter()
    first = None
    with httpx.Client(timeout=httpx.Timeout(a.max_wait_s, connect=30)) as c:
        while time.perf_counter() - t0 < a.max_wait_s:
            ts = time.perf_counter()
            try:
                r = c.get(f"{base}/health", timeout=max(5, a.max_wait_s - (ts - t0)))
                attempts.append({"t_s": round(ts - t0, 2), "status": r.status_code,
                                 "ms": round((time.perf_counter() - ts) * 1000, 1)})
                if r.status_code == 200 and r.headers.get("content-type", "").startswith("application/json"):
                    first = {"seconds_until_first_200": round(time.perf_counter() - t0, 2), "body": r.json()}
                    break
            except Exception as e:
                attempts.append({"t_s": round(ts - t0, 2), "error": type(e).__name__})
            time.sleep(5)   # polite retry
        warm = []
        for _ in range(3):
            time.sleep(1)
            ts = time.perf_counter()
            r = c.get(f"{base}/health")
            warm.append({"status": r.status_code, "ms": round((time.perf_counter() - ts) * 1000, 1)})
    res = {"base_url": base, "measured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "idle_minutes_before": round(idle_min, 1), "cold_start": first, "attempts": attempts,
           "warm_health_requests": warm,
           "note": "time from sending the first request until the first HTTP 200 JSON answer, client in India"}
    out = ROOT / "reports/metrics/cold_start.json"
    out.write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
