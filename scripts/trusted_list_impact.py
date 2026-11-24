"""How much does the trusted-domain list change the API's answers?

Runs the 86 real-world benign URLs and the OpenPhish snapshot through the API
(in-process TestClient) with the list ON and with ?model_only=true (OFF).
Writes reports/metrics/trusted_list_impact.json. Notebook metrics stay model-only.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402
from src.modeling import load_openphish, load_realworld  # noqa: E402


def run(client, urls, model_only):
    out = []
    for i in range(0, len(urls), 100):
        r = client.post("/predict/batch", json={"urls": urls[i:i + 100]}, params={"model_only": str(model_only).lower()})
        r.raise_for_status()
        out += r.json()["results"]
    return out


def main():
    rw = load_realworld()
    op = load_openphish()
    rows, details = [], {}
    with TestClient(app) as c:
        for name, urls, truth in [("real-world benign (86)", rw["url"].tolist(), 0),
                                  (f"OpenPhish phishing ({len(op)})", op["url_original"].tolist(), 1)]:
            on, off = run(c, urls, False), run(c, urls, True)
            flag_on, flag_off = sum(r["is_malicious"] for r in on), sum(r["is_malicious"] for r in off)
            by_list = sum(r["decided_by"] == "trusted_list" for r in on)
            rows.append({"set": name, "URLs": len(urls),
                         "flagged malicious (list OFF, model only)": flag_off,
                         "flagged malicious (list ON)": flag_on,
                         "decided by trusted list": by_list,
                         "metric": "false positives" if truth == 0 else "recall",
                         "value OFF": flag_off if truth == 0 else round(flag_off / len(urls), 4),
                         "value ON": flag_on if truth == 0 else round(flag_on / len(urls), 4)})
            details[name] = [{"url": u, "on": a["verdict"], "off": b["verdict"], "decided_by": a["decided_by"],
                              "probability": a["probability"]}
                             for u, a, b in zip(urls, on, off) if a["verdict"] != b["verdict"] or a["decided_by"] == "trusted_list"]
    tab = pd.DataFrame(rows)
    print(tab.to_string(index=False))
    for k, v in details.items():
        changed = [d for d in v if d["on"] != d["off"]]
        print(f"\n{k}: {len(changed)} verdicts changed by the list")
        for d in changed:
            print(f"   {d['off']:>9} -> {d['on']:<9} p={d['probability']:.3f}  {d['url'][:90]}")
    out = ROOT / "reports" / "metrics" / "trusted_list_impact.json"
    out.write_text(json.dumps({"table": rows, "changed_or_trusted": details}, indent=2))
    print("\nsaved", out.relative_to(ROOT))


if __name__ == "__main__":
    main()
