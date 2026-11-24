"""Record the live API's answers for the demo URL list (docs/06_demo_script.md).

Usage: python scripts/demo_calls.py --base-url https://malicious-url-api.onrender.com
Sends 1 GET /health + 2 POST /predict per URL (normal and ?model_only=true), 0.5 s apart.
Writes reports/metrics/demo_live_results.json, including the time of the LAST request
(needed for the cold-start idle window).
"""
import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.modeling import load_openphish  # noqa: E402

SAFE_TAB, POPUP_ONLY = "SAFE TO OPEN IN A TAB", "POPUP ONLY"
FIXED = [
    ("safe", SAFE_TAB, "https://www.google.com/search?q=random+forest+phishing+detection"),
    ("safe", SAFE_TAB, "https://www.youtube.com/watch?v=aircAruvnKk"),
    ("safe", SAFE_TAB, "https://www.mitaoe.ac.in"),
    ("safe", SAFE_TAB, "https://www.onlinesbi.sbi/"),
    ("safe", SAFE_TAB, "https://en.wikipedia.org/wiki/Random_forest"),
    ("safe", SAFE_TAB, "https://github.com/deva104/MaliciousURL"),
    ("safe", SAFE_TAB, "https://www.amazon.in/Apple-MacBook-Chip-13-inch-256GB/dp/B08N5W4NNB"),
    ("safe", SAFE_TAB, "https://www.irctc.co.in"),
    ("harmless-but-suspicious (documentation IP)", SAFE_TAB, "http://203.0.113.45/secure/login/verify-account.php"),
    ("harmless-but-suspicious (documentation IP)", SAFE_TAB, "http://198.51.100.7/paypal/login/verify"),
    ("harmless-but-suspicious (documentation IP)", SAFE_TAB, "http://192.0.2.10/paypal.com/webscr/cmd=login"),
    ("look-alike", POPUP_ONLY, "paypal.com.secure-account-verify.xyz/signin"),
    ("look-alike", POPUP_ONLY, "http://xn--pypal-4ve.com/login"),
    ("look-alike", POPUP_ONLY, "bit.ly/3abcXYZ"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--pause", type=float, default=0.5)
    a = ap.parse_args()
    op = load_openphish()
    picks = random.Random(42).sample(op["url_original"].tolist(), 8)   # fixed, reproducible choice
    urls = FIXED + [("OpenPhish (live phishing)", POPUP_ONLY, u) for u in picks]
    rows, n_req = [], 0
    with httpx.Client(base_url=a.base_url.rstrip("/"), timeout=180) as c:
        t = time.perf_counter()
        h = c.get("/health"); n_req += 1
        first = {"status": h.status_code, "ms": round((time.perf_counter() - t) * 1000, 1), "body": h.json()}
        for group, open_rule, u in urls:
            rec = {"group": group, "open": open_rule, "url": u}
            for mode, params in [("normal", {}), ("model_only", {"model_only": "true"})]:
                time.sleep(a.pause)
                r = c.post("/predict", json={"url": u}, params=params); n_req += 1
                b = r.json()
                rec[mode] = {"status": r.status_code, "verdict": b.get("verdict"), "probability": b.get("probability"),
                             "decided_by": b.get("decided_by"), "reasons": b.get("reasons"),
                             "error": b.get("error"), "detail": b.get("detail")}
            last = datetime.now(timezone.utc)
            rows.append(rec)
            n = rec["normal"]; m = rec["model_only"]
            print(f"{n['verdict'] or n['status']!s:>9} ({n['decided_by']}) | model-only {m['verdict'] or m['status']!s:>9} "
                  f"p={m['probability'] if m['probability'] is not None else float('nan'):.3f} | {u[:70]}", flush=True)
    out = {"base_url": a.base_url, "requests_sent": n_req, "first_health": first,
           "last_request_utc": last.isoformat(timespec="seconds"),
           "last_request_local": last.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
           "results": rows}
    p = ROOT / "reports/metrics/demo_live_results.json"
    p.write_text(json.dumps(out, indent=2))
    print(f"\n{n_req} requests; LAST REQUEST at {out['last_request_local']} ({out['last_request_utc']} UTC)")
    print("saved", p.relative_to(ROOT))


if __name__ == "__main__":
    main()
