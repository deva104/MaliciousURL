"""Tests for src/predict.py (need models/best_model.joblib + model_metadata.json from notebook 02)."""
import math

import pandas as pd
import pytest

from src.config import EXTERNAL, MODELS

pytestmark = pytest.mark.skipif(not (MODELS / "best_model.joblib").exists()
                                or not (MODELS / "model_metadata.json").exists(),
                                reason="run notebooks/02_model_training_evaluation.ipynb first")


def _api():
    from src import predict
    return predict


def test_output_schema():
    r = _api().predict_url("https://www.example.com/")
    assert set(r) == {"url", "normalized_url", "probability", "is_malicious", "threshold", "reasons"}
    assert 0.0 <= r["probability"] <= 1.0 and isinstance(r["reasons"], list) and len(r["reasons"]) <= 3


def test_google_variants_same_output():
    variants = ["google.com", "https://www.google.com/", "http://google.com", "HTTPS://WWW.GOOGLE.COM/#x"]
    out = [_api().predict_url(v) for v in variants]
    assert len({o["probability"] for o in out}) == 1
    assert len({o["is_malicious"] for o in out}) == 1
    assert all(o["normalized_url"] == "google.com" for o in out)


def test_ip_host_phishing_style_url_is_high():
    r = _api().predict_url("http://185.234.72.19/paypal.com/webscr/login.php?cmd=_login-run&account=verify")
    assert r["probability"] >= 0.8 and r["is_malicious"]
    assert "Host is an IP address, not a domain name" in r["reasons"]


@pytest.mark.parametrize("bad", ["", " ", None, "://", "http://", "[", "\x00\x01", "a" * 5000, "日本語.jp/パス",
                                 "http://[::1", "javascript:alert(1)"])
def test_garbage_does_not_crash(bad):
    r = _api().predict_url(bad)
    assert math.isfinite(r["probability"])


def test_batch_equals_single():
    urls = ["google.com", "https://github.com/login", "http://192.168.1.5/a.exe", "paypal.com.secure-login.tk",
            "https://www.amazon.in/dp/B08N5W4NNB", ""]
    batch = _api().predict_batch(urls)
    single = [_api().predict_url(u) for u in urls]
    assert batch == single


def test_realworld_csv_loads_and_scores():
    rw = pd.read_csv(EXTERNAL / "realworld_benign_urls.csv")
    assert list(rw.columns) == ["url", "category", "note"] and len(rw) >= 80
    assert rw["url"].str.startswith("https://").all()
    out = _api().predict_batch(rw["url"].head(5))
    assert len(out) == 5
