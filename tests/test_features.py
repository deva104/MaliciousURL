"""Unit tests for src/features.py (run: python -m pytest -q)."""
import math

import numpy as np
import pandas as pd
import pytest

from src.features import (LEXICAL_FEATURES, UrlFeatureExtractor, extract_features,
                          extract_features_batch, normalize_url, parse_url)


# --------------------------------------------------------------------------- #
# normalisation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw, expected", [
    ("google.com", "google.com"),
    ("https://www.google.com/", "google.com"),
    ("HTTP://WWW.Google.COM", "google.com"),
    ("  https://www2.example.com/Path/To/Page/  ", "example.com/Path/To/Page"),
    ("https://www.google.com/search?q=X#results", "google.com/search?q=X"),
    ("ftp://files.example.org:21/pub/", "files.example.org:21/pub"),
    ("example.com/?", "example.com"),
    ("example.com/?a=1", "example.com?a=1"),
])
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


def test_path_case_is_preserved():
    assert normalize_url("https://Example.com/AbC") == "example.com/AbC"


def test_google_variants_have_identical_features():
    variants = ["google.com", "https://www.google.com/", "http://google.com",
                "WWW.GOOGLE.COM/", "https://www.google.com/#top"]
    feats = [extract_features(v) for v in variants]
    for f in feats[1:]:
        assert f == feats[0]


def test_no_scheme_or_www_features():
    for name in LEXICAL_FEATURES:
        assert "https" not in name and "scheme" not in name and "www" not in name


# --------------------------------------------------------------------------- #
# host structure
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    "http://192.168.0.1/login.php",
    "http://3232235521/",                 # decimal IPv4
    "http://0xC0A80001/",                 # hex IPv4
    "http://[2001:db8::1]:8080/admin",    # IPv6 with port
])
def test_ip_hosts_are_detected(url):
    assert extract_features(url)["has_ip_host"] == 1


def test_normal_domain_is_not_ip():
    assert extract_features("https://www.example.com/123")["has_ip_host"] == 0


def test_ipv6_port_parsed():
    p = parse_url("http://[2001:db8::1]:8080/admin")
    assert p.host == "2001:db8::1" and p.port == "8080"
    assert extract_features("http://[2001:db8::1]:8080/admin")["has_port"] == 1


def test_punycode_is_detected():
    assert extract_features("http://xn--pypal-4ve.com/signin")["has_punycode"] == 1
    assert extract_features("http://paypal.com/signin")["has_punycode"] == 0


def test_tld_in_subdomain_and_brand_flag():
    f = extract_features("paypal.com.secure-login.tk")
    assert f["tld_in_subdomain"] == 1
    assert f["brand_in_non_registered_part"] == 1
    assert f["suspicious_tld"] == 1
    p = parse_url("paypal.com.secure-login.tk")
    assert p.registered_domain == "secure-login.tk"


def test_brand_on_its_own_domain_is_not_flagged():
    for url in ["https://www.paypal.com/signin", "https://accounts.google.com/login",
                "https://outlook.office365.com/mail"]:
        assert extract_features(url)["brand_in_non_registered_part"] == 0, url


def test_userinfo_trick():
    f = extract_features("http://paypal.com@evil.example.net/login")
    p = parse_url("http://paypal.com@evil.example.net/login")
    assert f["has_at_symbol"] == 1
    assert p.host == "evil.example.net"
    assert f["brand_in_non_registered_part"] == 1


def test_shortener_and_embedded_url():
    assert extract_features("https://bit.ly/3abcDEF")["is_shortener"] == 1
    assert extract_features("https://example.com/redirect?to=https://evil.tk")["embedded_url"] == 1
    assert extract_features("https://example.com/a//b")["double_slash_in_path"] == 1


def test_risky_extension_php_html():
    f = extract_features("http://evil.example.com/download/update.exe")
    assert f["risky_file_extension"] == 1
    assert extract_features("site.com/index.php?option=com_content")["has_php"] == 1
    assert extract_features("site.com/page.html")["has_html"] == 1


def test_counts_on_known_url():
    f = extract_features("https://www.example.com/a-b/c_d?x=1&y=2")
    # normalised: example.com/a-b/c_d?x=1&y=2
    assert f["url_len"] == len("example.com/a-b/c_d?x=1&y=2")
    assert f["num_query_params"] == 2
    assert f["num_path_segments"] == 2
    assert f["num_hyphens"] == 1 and f["num_underscores"] == 1
    assert f["num_subdomains"] == 0          # www. was removed
    assert f["registered_domain_len"] == len("example.com")


# --------------------------------------------------------------------------- #
# robustness
# --------------------------------------------------------------------------- #
GARBAGE = [
    "", " ", None, float("nan"), "://", "http://", "////", "?", "#", "@", "[", "]:",
    "http://[::1", "http://user:pass@host.com:99999/", "日本語.jp/パス?キー=値",
    "http://xn--/", "a" * 5000, "\x00\x01\x02", "javascript:alert(1)",
    "http://例え.テスト/", "..", "http://.com", "%%%%", 12345, b"bytes",
]


@pytest.mark.parametrize("bad", GARBAGE)
def test_garbage_does_not_crash(bad):
    f = extract_features(bad)
    assert list(f) == list(LEXICAL_FEATURES)
    assert all(isinstance(v, (int, float)) and math.isfinite(v) for v in f.values())


def test_batch_equals_single():
    urls = ["google.com", "https://www.google.com/search?q=x", "paypal.com.secure-login.tk",
            "http://192.168.0.1/a.exe", "", "日本語.jp/パス", "bit.ly/x", "google.com"]
    batch = extract_features_batch(pd.Series(urls))
    single = pd.DataFrame([extract_features(u) for u in urls])
    pd.testing.assert_frame_equal(batch.reset_index(drop=True), single, check_dtype=False)
    assert np.isfinite(batch.to_numpy(dtype=float)).all()


# --------------------------------------------------------------------------- #
# fitted extractor (TLD target encoding)
# --------------------------------------------------------------------------- #
def test_extractor_tld_encoding_and_unseen_prior():
    urls = ["a.com", "b.com", "c.com", "d.tk", "e.tk", "f.org"]
    y = [0, 0, 1, 1, 1, 0]
    fx = UrlFeatureExtractor(m=2).fit(urls, y)
    prior = 3 / 6
    assert fx.prior_ == pytest.approx(prior)
    assert fx.tld_rates_["tk"] == pytest.approx((2 + 2 * prior) / (2 + 2))
    X = fx.transform(["new.tk", "never-seen.zzzunknowntld", "x.com"])
    assert list(X.columns) == fx.feature_names
    assert X.loc[0, "tld_malicious_rate"] == pytest.approx(fx.tld_rates_["tk"])
    assert X.loc[1, "tld_malicious_rate"] == pytest.approx(prior)   # unseen -> prior
    one = fx.transform_one("https://www.x.com/")
    assert one.shape == (1, len(fx.feature_names))


def test_transform_one_fast_path_equals_batch_transform():
    urls = ["a.com", "b.tk/login", "c.org", "d.tk", "http://192.168.1.1/x.exe", "", "日本語.jp/パス",
            "https://www.google.com/search?q=x", "paypal.com.secure-login.tk", "never.zzzunknowntld"]
    fx = UrlFeatureExtractor(m=2).fit(urls[:4], [0, 1, 0, 1])
    batch = fx.transform(urls).reset_index(drop=True)
    one = pd.concat([fx.transform_one(u) for u in urls], ignore_index=True)
    pd.testing.assert_frame_equal(one, batch, check_dtype=False)


def test_group_folds_keep_groups_together_and_balanced():
    rng = np.random.default_rng(1)
    groups = rng.choice([f"d{i}" for i in range(2000)], size=20_000)
    fold = UrlFeatureExtractor.group_folds(groups, n_splits=5, random_state=42)
    df = pd.DataFrame({"g": groups, "f": fold})
    assert (df.groupby("g")["f"].nunique() == 1).all()          # no group in two folds
    share = df["f"].value_counts(normalize=True)
    assert set(share.index) == set(range(5)) and share.between(0.17, 0.23).all()
    again = UrlFeatureExtractor.group_folds(groups, n_splits=5, random_state=42)
    assert (fold == again).all()                                 # deterministic


def test_fit_transform_is_out_of_fold():
    rng = np.random.default_rng(0)
    urls = [f"site{i}.{t}" for i, t in enumerate(rng.choice(["com", "tk", "org"], 300))]
    y = rng.integers(0, 2, 300)
    fx = UrlFeatureExtractor(m=10, n_splits=5)
    X_oof = fx.fit_transform(urls, y, groups=[u.split(".")[0] for u in urls])
    X_full = fx.transform(urls)
    # OOF values differ from in-sample values (no self-leakage) but stay in [0, 1]
    assert not np.allclose(X_oof["tld_malicious_rate"], X_full["tld_malicious_rate"])
    assert X_oof["tld_malicious_rate"].between(0, 1).all()
