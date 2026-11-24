"""Async load test for the running API.

Usage:
    python scripts/load_test.py --base-url http://127.0.0.1:8000 --n 1000 --concurrency 20 \
        --out reports/metrics/api_load_test.json

Sends POST /predict requests with a mix of URLs: real-world benign, OpenPhish
and synthetic unique URLs (cache misses), so the numbers include real model
work and not only cache hits. Reports p50/p95/p99 latency and requests/sec.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import platform
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def url_pool(n: int, seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    real = []
    rw = ROOT / "data" / "external" / "realworld_benign_urls.csv"
    if rw.exists():
        import csv
        with open(rw, encoding="utf-8") as f:
            real += [r["url"] for r in csv.DictReader(f)]
    for p in sorted((ROOT / "data" / "external").glob("openphish_feed_*.txt"))[-1:]:
        real += [u.strip() for u in p.read_text(encoding="utf-8").splitlines() if u.strip()]
    urls = []
    for i in range(n):
        if real and rng.random() < 0.5:
            urls.append(rng.choice(real))
        else:   # unique -> cache miss
            urls.append(f"https://www.example{i}.com/account/{rng.randint(1, 10**6)}/view?id={i}")
    return urls


async def run(base_url: str, n: int, concurrency: int, timeout: float) -> dict:
    urls = url_pool(n)
    lat, codes, errors = [], {}, 0
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        t_health = time.perf_counter()
        h = await client.get("/health")
        first_ms = (time.perf_counter() - t_health) * 1000

        async def one(u: str):
            nonlocal errors
            async with sem:
                t = time.perf_counter()
                try:
                    r = await client.post("/predict", json={"url": u})
                    codes[r.status_code] = codes.get(r.status_code, 0) + 1
                except Exception:
                    errors += 1
                    return
                lat.append((time.perf_counter() - t) * 1000)

        t0 = time.perf_counter()
        await asyncio.gather(*(one(u) for u in urls))
        wall = time.perf_counter() - t0
    q = statistics.quantiles(lat, n=100) if len(lat) >= 2 else [float("nan")] * 99
    return {
        "base_url": base_url, "requests": n, "concurrency": concurrency, "completed": len(lat),
        "errors": errors, "status_codes": {str(k): v for k, v in sorted(codes.items())},
        "wall_time_s": round(wall, 3), "requests_per_s": round(len(lat) / wall, 1),
        "latency_ms": {"p50": round(q[49], 2), "p95": round(q[94], 2), "p99": round(q[98], 2),
                       "mean": round(statistics.mean(lat), 2), "max": round(max(lat), 2)},
        "first_health_ms": round(first_ms, 1), "health": h.json() if h.status_code == 200 else h.status_code,
        "client": platform.platform(), "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "about 50% real URLs (repeats -> cache hits) and 50% unique URLs (cache misses)",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--out", default=str(ROOT / "reports" / "metrics" / "api_load_test.json"))
    a = ap.parse_args()
    res = asyncio.run(run(a.base_url, a.n, a.concurrency, a.timeout))
    print(json.dumps(res, indent=2))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    return 0 if res["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
