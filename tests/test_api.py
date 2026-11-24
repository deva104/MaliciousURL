"""API tests (FastAPI TestClient). Needs models/best_model.joblib from Step 2."""
import time

import pytest

from src.config import MODELS

pytestmark = pytest.mark.skipif(not (MODELS / "best_model.joblib").exists(), reason="run notebook 02 first")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from api.main import app
    with TestClient(app) as c:          # runs the lifespan (load + warm-up)
        yield c


def post(client, url, **params):
    return client.post("/predict", json={"url": url}, params=params)


def test_root_and_health(client):
    assert client.get("/").json()["docs"] == "/docs"
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["model_loaded"] is True and h["uptime_s"] >= 0
    assert "@" in h["model_version"]


def test_response_contract(client):
    r = post(client, "https://www.example.com/")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"url", "normalized_url", "verdict", "is_malicious", "probability", "threshold",
                         "decided_by", "reasons", "latency_ms", "model_version"}
    assert body["verdict"] in ("malicious", "safe") and body["decided_by"] in ("model", "trusted_list")


def test_google_variants_identical(client):
    out = [post(client, u).json() for u in ["google.com", "https://www.google.com/", "HTTPS://WWW.GOOGLE.COM/?x"]]
    # the first two normalise identically; the third adds a query (?x) but must give the same verdict
    assert out[0]["probability"] == out[1]["probability"]
    assert {o["verdict"] for o in out} == {"safe"}
    assert all(o["decided_by"] == "trusted_list" for o in out)


def test_obvious_phishing_is_malicious(client):
    r = post(client, "http://185.234.72.19/paypal.com/signin/webscr/login.php?cmd=_login-run&account=verify").json()
    assert r["verdict"] == "malicious" and r["decided_by"] == "model"
    assert r["probability"] >= r["threshold"] and r["reasons"]


@pytest.mark.parametrize("url", ["https://sites.google.com/view/paypal-login-verify",
                                 "https://secure-login-update.github.io/",
                                 "https://docs.google.com/forms/d/e/1FAIpQLSf/viewform",
                                 "https://google.com/url?q=http://evil.example.tk"])
def test_user_content_hosts_bypass_trusted_list(client, url):
    assert post(client, url).json()["decided_by"] == "model"


def test_model_only_flag(client):
    a = post(client, "https://www.paypal.com/signin").json()
    b = post(client, "https://www.paypal.com/signin", model_only="true").json()
    assert a["decided_by"] == "trusted_list" and a["verdict"] == "safe"
    assert b["decided_by"] == "model" and b["probability"] == a["probability"]


@pytest.mark.parametrize("bad", ["", "   ", "a" * 2001, "\x00\x01\x02", "://", "http://", "justtext"])
def test_invalid_input_422(client, bad):
    r = post(client, bad)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_request" and r.json()["detail"][0]["message"]


def test_missing_field_422(client):
    assert client.post("/predict", json={}).status_code == 422


def test_batch_limit_422(client):
    r = client.post("/predict/batch", json={"urls": ["https://example.com"] * 101})
    assert r.status_code == 422


def test_batch_equals_single(client):
    urls = ["google.com", "https://github.com/login", "http://192.168.1.5/a.exe",
            "paypal.com.secure-login.tk", "https://www.amazon.in/dp/B08N5W4NNB"]
    batch = client.post("/predict/batch", json={"urls": urls}).json()
    assert batch["count"] == len(urls)
    single = [post(client, u).json() for u in urls]
    strip = lambda d: {k: v for k, v in d.items() if k != "latency_ms"}  # noqa: E731
    assert [strip(b) for b in batch["results"]] == [strip(s) for s in single]


def test_cors_for_chrome_extension(client):
    r = client.options("/predict", headers={"Origin": "chrome-extension://abc",
                                            "Access-Control-Request-Method": "POST",
                                            "Access-Control-Request-Headers": "content-type"})
    assert r.headers.get("access-control-allow-origin") == "*"
    r2 = client.post("/predict", json={"url": "google.com"}, headers={"Origin": "chrome-extension://abc"})
    assert r2.headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-credentials" not in r2.headers


def test_model_info(client):
    m = client.get("/model-info").json()
    assert m["n_features"] == 43 and 0 < m["threshold"] < 1 and "test" in m["metrics"]


def test_local_latency_reasonable(client):
    urls = [f"https://www.site{i}.example.com/path/{i}?q={i}" for i in range(50)]   # cache misses
    t = time.perf_counter()
    for u in urls:
        assert post(client, u, model_only="true").status_code == 200
    per_request_ms = (time.perf_counter() - t) * 1000 / len(urls)
    assert per_request_ms < 100, per_request_ms
