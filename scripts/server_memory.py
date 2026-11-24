"""RSS of the running API server process (found by its listening port).

Usage: python scripts/server_memory.py --port 8000 [--label after_load_test]
Appends to reports/metrics/api_server_memory.json.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--label", default="after_startup")
    a = ap.parse_args()
    pids = {c.pid for c in psutil.net_connections(kind="tcp") if c.laddr and c.laddr.port == a.port
            and c.status == psutil.CONN_LISTEN and c.pid}
    procs = [psutil.Process(p) for p in pids]
    rec = {"label": a.label, "port": a.port, "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "processes": [{"pid": p.pid, "name": p.name(), "rss_mb": round(p.memory_info().rss / 1e6, 1)} for p in procs]}
    rec["total_rss_mb"] = round(sum(x["rss_mb"] for x in rec["processes"]), 1)
    out = ROOT / "reports" / "metrics" / "api_server_memory.json"
    data = json.loads(out.read_text()) if out.exists() else []
    data.append(rec)
    out.write_text(json.dumps(data, indent=2))
    print(json.dumps(rec, indent=2))


if __name__ == "__main__":
    main()
