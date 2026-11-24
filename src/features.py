"""URL normalisation + lexical feature extraction.

This module is shared by the training notebooks AND the FastAPI service, so the
exact same code turns a URL into a feature vector in both places.

Design rules
------------
* Pure functions, no network access. tldextract is created with
  ``suffix_list_urls=()`` and ``cache_dir=None`` so it only uses the Public Suffix
  List snapshot bundled inside the package: it never downloads or writes files.
* Every feature is computed on the NORMALISED url (see ``normalize_url``):
  scheme, ``www.`` prefixes, fragments and trailing slashes are removed, because
  in our training data they are artefacts of how each source was collected and
  not properties of malicious URLs (see the EDA notebook, section 3).
* There are deliberately NO features for scheme / https / www.
* Never raises on garbage input: worst case it returns a vector of zeros.

Public API
----------
normalize_url(url)                -> str
parse_url(url)                    -> ParsedUrl (normalised parts + tldextract result)
extract_features(url)             -> dict  (lexical features, LEXICAL_FEATURES order)
extract_features_batch(urls)      -> pd.DataFrame (same values, fast path for Series)
UrlFeatureExtractor               -> fitted transformer that adds the TLD target
                                     encoding (tld_malicious_rate); saved with joblib.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Sequence

import numpy as np
import pandas as pd
import tldextract

# --------------------------------------------------------------------------- #
# Constants (kept in one place so the API, tests and the report agree)
# --------------------------------------------------------------------------- #

#: Words that phishing / scam URLs use to look like account or payment pages.
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login", "logon", "signin", "sign-in", "verify", "verification", "validate",
    "account", "update", "secure", "security", "banking", "confirm", "password",
    "passwd", "credential", "wallet", "webscr", "ebayisapi", "billing", "invoice",
    "payment", "suspend", "unlock", "recover", "free", "bonus", "lucky", "prize",
    "admin", "wp-",
)

#: Commonly phished brands (global + Indian banks). Brands of <= 5 letters are
#: matched as whole tokens to avoid false hits ("chase" inside "purchase").
BRANDS: tuple[str, ...] = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "onedrive",
    "google", "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp",
    "linkedin", "twitter", "dropbox", "adobe", "docusign", "ebay", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hsbc", "sbi", "hdfc", "icici",
    "binance", "coinbase", "metamask", "dhl", "fedex", "usps", "yahoo", "steam",
)

#: Public URL-shortening services (matched on the registered domain or host).
SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "rb.gy", "buff.ly", "adf.ly", "bit.do", "shorte.st", "tiny.cc",
    "rebrand.ly", "t.ly", "v.gd", "lnkd.in", "db.tt", "qr.ae", "tr.im", "cli.gs",
    "shorturl.at", "s.id", "clck.ru", "j.mp", "trib.al", "wp.me", "x.co", "u.to",
    "soo.gd", "short.io", "bl.ink", "tiny.one", "shrtco.de",
})

#: TLDs repeatedly reported as heavily abused for phishing:
#:  - Freenom ccTLDs .tk .ml .ga .cf .gq: 60% of all ccTLD phishing domains in
#:    Nov 2022 (Interisle, "Phishing Landscape 2023").
#:  - .top: Spamhaus "Domain Reputation Update Apr-Sep 2025" (+50% abuse).
#:  - .shop .xyz: Interisle 2024 data via KrebsOnSecurity (Dec 2024).
#:  - .xin .bond .help .win .cfd: top-5 "phishing score" TLDs in Interisle,
#:    "Phishing Landscape 2025".
#: The data-driven ``tld_malicious_rate`` is the main TLD feature; this flag is a
#: prior-knowledge signal that also works for TLDs unseen in training.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "top", "shop", "xyz",
    "xin", "bond", "help", "win", "cfd",
})

#: Second-level labels that betray a domain name hidden in a subdomain,
#: e.g. ``paypal.com.evil.tk``.
COMMON_TLD_LABELS: frozenset[str] = frozenset({
    "com", "net", "org", "info", "biz", "gov", "edu", "mil", "co", "io",
})

#: File extensions that are commonly used to deliver malware.
RISKY_EXTENSIONS: tuple[str, ...] = (
    "exe", "apk", "zip", "rar", "scr", "js", "bat", "dll", "bin",
    "msi", "jar", "vbs", "ps1", "cmd", "iso", "7z",
)

#: Order of the lexical features (stateless, computed by ``extract_features``).
LEXICAL_FEATURES: tuple[str, ...] = (
    # length
    "url_len", "host_len", "path_len", "query_len", "registered_domain_len", "tld_len",
    # counts
    "num_dots", "num_hyphens", "num_underscores", "num_slashes", "num_question_marks",
    "num_equals", "num_ampersands", "num_at", "num_percent", "num_tilde",
    "num_digits", "num_letters", "num_other_special", "num_query_params",
    "num_path_segments", "host_num_dots", "host_num_hyphens", "host_num_digits",
    # statistics
    "digit_ratio", "letter_ratio", "special_char_ratio", "url_entropy", "host_entropy",
    "longest_token_len", "avg_token_len", "max_consecutive_repeated_char",
    "host_vowel_ratio",
    # host structure
    "num_subdomains", "has_ip_host", "has_port", "has_punycode", "has_at_symbol",
    "tld_in_subdomain", "double_slash_in_path", "embedded_url",
    # lexical signals
    "suspicious_keyword_count", "brand_in_non_registered_part", "is_shortener",
    "suspicious_tld", "risky_file_extension", "has_php", "has_html",
)

#: Features produced by fitting on training labels (added by UrlFeatureExtractor).
ENCODED_FEATURES: tuple[str, ...] = ("tld_malicious_rate",)

#: name -> (group, what it measures, why it can signal a malicious URL)
FEATURE_DESCRIPTIONS: dict[str, tuple[str, str, str]] = {
    "url_len": ("length", "characters in the normalised URL", "phishing URLs pad the URL to hide the real domain"),
    "host_len": ("length", "characters in the host name", "long hosts stack fake subdomains (paypal.com.x.y.tk)"),
    "path_len": ("length", "characters in the path", "deep or random paths are typical of compromised sites / kits"),
    "query_len": ("length", "characters in the query string", "long queries carry tracking ids, redirects or encoded payloads"),
    "registered_domain_len": ("length", "length of the registered domain (example.co.uk)", "throw-away domains are often long or random"),
    "tld_len": ("length", "length of the public suffix", "new gTLDs (.online, .support) are longer than .com / .in"),
    "num_dots": ("count", "'.' in URL", "many dots = many subdomains or file-like names"),
    "num_hyphens": ("count", "'-' in URL", "hyphenated look-alike domains (secure-paypal-login)"),
    "num_underscores": ("count", "'_' in URL", "unusual in hosts; common in kit file names"),
    "num_slashes": ("count", "'/' in URL", "path depth"),
    "num_question_marks": ("count", "'?' in URL", "more than one '?' hints at an embedded URL"),
    "num_equals": ("count", "'=' in URL", "number of parameter assignments"),
    "num_ampersands": ("count", "'&' in URL", "number of extra parameters"),
    "num_at": ("count", "'@' in URL", "'@' makes browsers ignore everything before it"),
    "num_percent": ("count", "'%' in URL", "percent-encoding is used to obfuscate"),
    "num_tilde": ("count", "'~' in URL", "user home directories on shared hosting"),
    "num_digits": ("count", "digits in URL", "random ids, IPs, generated names"),
    "num_letters": ("count", "letters in URL", "size of the alphabetic part"),
    "num_other_special": ("count", "other non-alphanumeric chars (; , + ! * ...)", "rare in normal URLs, common in obfuscation"),
    "num_query_params": ("count", "parameters in the query", "phishing kits pass victim data in parameters"),
    "num_path_segments": ("count", "non-empty '/'-separated path parts", "path depth"),
    "host_num_dots": ("count", "'.' in host", "subdomain depth"),
    "host_num_hyphens": ("count", "'-' in host", "look-alike hosts"),
    "host_num_digits": ("count", "digits in host", "generated / random hosts"),
    "digit_ratio": ("statistic", "digits / URL length", "machine-generated URLs are digit-heavy"),
    "letter_ratio": ("statistic", "letters / URL length", "human-readable URLs are letter-heavy"),
    "special_char_ratio": ("statistic", "non-alphanumeric chars / URL length", "obfuscation and long queries"),
    "url_entropy": ("statistic", "Shannon entropy of the URL (bits/char)", "random strings have high entropy"),
    "host_entropy": ("statistic", "Shannon entropy of the host", "algorithmically generated domains (DGA)"),
    "longest_token_len": ("statistic", "longest alphanumeric token", "long random tokens / hashes"),
    "avg_token_len": ("statistic", "mean alphanumeric token length", "natural words are short"),
    "max_consecutive_repeated_char": ("statistic", "longest run of one repeated character", "padding tricks (----, 0000)"),
    "host_vowel_ratio": ("statistic", "vowels / letters in host", "random hosts have unnatural vowel ratios"),
    "num_subdomains": ("host", "labels before the registered domain (www removed)", "brand names hidden in subdomains"),
    "has_ip_host": ("host", "host is an IPv4 (dotted/hex/decimal) or IPv6 address", "no domain name = no accountability"),
    "has_port": ("host", "explicit port number", "non-standard ports are rare for real sites"),
    "has_punycode": ("host", "host contains 'xn--' (internationalised)", "homograph attacks (pаypal with Cyrillic a)"),
    "has_at_symbol": ("host", "'@' present", "user-info trick http://paypal.com@evil.net"),
    "tld_in_subdomain": ("host", "a label like com/net/org inside the subdomain", "paypal.com.evil.tk pattern"),
    "double_slash_in_path": ("host", "'//' inside the path", "open-redirect style URLs"),
    "embedded_url": ("host", "http(s): or www. inside path/query", "redirect chains to another site"),
    "suspicious_keyword_count": ("lexical", "occurrences of words like login, verify, account", "social-engineering vocabulary"),
    "brand_in_non_registered_part": ("lexical", "a well-known brand in subdomain/path while the domain is not that brand", "impersonation (apple.id-verify.xyz/apple)"),
    "is_shortener": ("lexical", "domain is a URL shortener", "hides the real destination"),
    "suspicious_tld": ("lexical", "TLD on a published most-abused list", "cheap / free TLDs are used for throw-away domains"),
    "risky_file_extension": ("lexical", "path ends in .exe .apk .zip .js ...", "direct malware download"),
    "has_php": ("lexical", "'.php' in path", "phishing kits / compromised CMS pages are mostly PHP"),
    "has_html": ("lexical", "'.htm(l)' in path", "static phishing pages"),
    "tld_malicious_rate": ("encoded", "smoothed share of malicious URLs with this TLD (train only)", "data-driven TLD reputation"),
}

#: Binary 0/1 features (useful for EDA and for checks).
BINARY_FEATURES: tuple[str, ...] = (
    "has_ip_host", "has_port", "has_punycode", "has_at_symbol", "tld_in_subdomain",
    "double_slash_in_path", "embedded_url", "brand_in_non_registered_part",
    "is_shortener", "suspicious_tld", "risky_file_extension", "has_php", "has_html",
)

IP_TLD = "<ip>"      # pseudo-TLD for IP hosts
NO_TLD = "<none>"    # pseudo-TLD when no public suffix is found

# --------------------------------------------------------------------------- #
# Compiled regexes
# --------------------------------------------------------------------------- #
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_WWW_RE = re.compile(r"^(?:www\d*\.)+", re.IGNORECASE)
_AUTHORITY_RE = re.compile(r"^([^/?\\]*)(.*)$", re.DOTALL)
_NUMERIC_HOST_RE = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$")
_TOKEN_SPLIT_RE = re.compile(r"[\W_]+", re.UNICODE)
_RUN_RE = re.compile(r"(.)\1*", re.DOTALL)
_EMBEDDED_URL_RE = re.compile(r"https?(?::|%3a)|www\.", re.IGNORECASE)
_KEYWORD_RE = re.compile("|".join(re.escape(k) for k in SUSPICIOUS_KEYWORDS))
_BRAND_RE = re.compile(
    "|".join(
        re.escape(b) if len(b) > 5 else rf"(?<![a-z]){re.escape(b)}(?![a-z])"
        for b in sorted(BRANDS, key=len, reverse=True)
    )
)
_RISKY_EXT_RE = re.compile(r"\.(?:" + "|".join(RISKY_EXTENSIONS) + r")$", re.IGNORECASE)
_BRAND_SET = frozenset(BRANDS)
_VOWELS = frozenset("aeiou")
_COUNTED_SPECIALS = ".-_/?=&@%~"

# Offline extractor: bundled Public Suffix List snapshot only, no cache files.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


# --------------------------------------------------------------------------- #
# Normalisation and parsing
# --------------------------------------------------------------------------- #
def _is_missing(v: object) -> bool:
    """None / NaN / pd.NA count as an empty URL."""
    if v is None or v is pd.NA:
        return True
    return isinstance(v, float) and math.isnan(v)


def _strip_www(hostport: str) -> str:
    """Remove leading www./www2./www.www. ... but never the last real label
    (``www.com`` stays ``www.com``)."""
    m = _WWW_RE.match(hostport)
    if m and "." in hostport[m.end():]:
        return hostport[m.end():]
    return hostport


def normalize_url(url: object) -> str:
    """Canonical form used for de-duplication and for ALL features.

    * strip surrounding whitespace, drop the ``#fragment``
    * remove any ``xxx://`` scheme prefix (http, https, ftp, ...)
    * lowercase the host part (authority) but NOT the path / query
    * remove a leading ``www.`` / ``www2.`` ... from the host
    * remove trailing ``/`` from the path; drop an empty ``?``
    * keep port, path and query

    >>> normalize_url("https://WWW.Google.com/Search?q=X#top")
    'google.com/Search?q=X'
    >>> normalize_url("google.com/")
    'google.com'
    """
    if _is_missing(url):
        return ""
    s = str(url).strip()
    if not s:
        return ""
    s = s.split("#", 1)[0]
    s = _SCHEME_RE.sub("", s, count=1)
    authority, rest = _AUTHORITY_RE.match(s).groups()
    authority = authority.lower()
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
        authority = f"{userinfo}@{_strip_www(hostport)}"
    else:
        authority = _strip_www(authority)
    path, sep, query = rest.partition("?")
    path = path.rstrip("/")
    return authority + path + (f"?{query}" if query else "")


@dataclass(frozen=True)
class ParsedUrl:
    """Pieces of a normalised URL."""
    normalized: str
    userinfo: str
    host: str
    port: str
    path: str
    query: str
    subdomain: str
    domain: str          # registered-domain label, e.g. "paypal" for paypal.co.uk
    suffix: str          # public suffix, e.g. "co.uk"
    is_ip: bool

    @property
    def registered_domain(self) -> str:
        return f"{self.domain}.{self.suffix}" if self.domain and self.suffix else ""

    @property
    def tld(self) -> str:
        """Category used for TLD statistics / target encoding."""
        if self.is_ip:
            return IP_TLD
        return self.suffix or NO_TLD

    @property
    def group_key(self) -> str:
        """Key for the grouped train/val/test split: the registered domain, or
        the bare host when there is none (IP addresses, unknown suffixes)."""
        return self.registered_domain or self.host


def is_ip_host(host: str) -> bool:
    """IPv4 (dotted, hex, octal or a single decimal integer) or IPv6."""
    if not host:
        return False
    if _NUMERIC_HOST_RE.match(host):
        return True
    if ":" in host:
        try:
            ipaddress.IPv6Address(host.split("%", 1)[0])
            return True
        except ValueError:
            return False
    return False


@lru_cache(maxsize=1_000_000)
def _split_host(host: str) -> tuple[str, str, str, bool]:
    """(subdomain, domain, suffix, is_ip) for a host, cached because hosts repeat."""
    if is_ip_host(host):
        return "", "", "", True
    try:
        ext = _TLD_EXTRACT(host)
        return ext.subdomain, ext.domain, ext.suffix, False
    except Exception:  # pragma: no cover - defensive, tldextract is robust
        return "", host, "", False


def _split_normalized(norm: str) -> tuple[str, str, str, str, str]:
    """(userinfo, host, port, path, query) of an already-normalised URL."""
    authority, rest = _AUTHORITY_RE.match(norm).groups()
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
    else:
        userinfo, hostport = "", authority
    port = ""
    if hostport.startswith("["):                      # [IPv6]:port
        end = hostport.find("]")
        if end == -1:
            host = hostport[1:]
        else:
            host = hostport[1:end]
            tail = hostport[end + 1:]
            port = tail[1:] if tail.startswith(":") else ""
    elif hostport.count(":") == 1:                    # host:port
        host, port = hostport.split(":")
    else:                                             # plain host / bare IPv6
        host = hostport
    host = host.strip(".")
    path, _, query = rest.partition("?")
    return userinfo, host, port, path, query


def parse_url(url: object, *, already_normalized: bool = False) -> ParsedUrl:
    if already_normalized:
        norm = "" if _is_missing(url) else str(url)
    else:
        norm = normalize_url(url)
    userinfo, host, port, path, query = _split_normalized(norm)
    sub, dom, suf, is_ip = _split_host(host)
    return ParsedUrl(norm, userinfo, host, port, path, query, sub, dom, suf, is_ip)


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #
def _entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    n = len(s)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _feature_tuple(p: ParsedUrl) -> tuple:
    """All lexical features of a parsed URL, in LEXICAL_FEATURES order."""
    u = p.normalized
    ul = u.lower()
    host, path, query = p.host, p.path, p.query
    rd = p.registered_domain
    n = len(u)

    n_digits = sum(map(str.isdigit, u))
    n_letters = sum(map(str.isalpha, u))
    counts = [u.count(ch) for ch in _COUNTED_SPECIALS]   # . - _ / ? = & @ % ~
    n_other = n - n_digits - n_letters - sum(counts)

    tokens = [t for t in _TOKEN_SPLIT_RE.split(u) if t]
    host_letters = [ch for ch in host if ch.isalpha()]
    sub_labels = [s for s in p.subdomain.split(".") if s]

    path_l = path.lower()
    non_registered = " ".join((p.userinfo, p.subdomain, path, query)).lower()
    brand_hit = (
        bool(_BRAND_RE.search(non_registered)) and p.domain not in _BRAND_SET
    )

    return (
        # length
        n, len(host), len(path), len(query), len(rd), len(p.suffix),
        # counts
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6],
        counts[7], counts[8], counts[9],
        n_digits, n_letters, n_other,
        sum(1 for q in query.split("&") if q) if query else 0,
        sum(1 for s in path.split("/") if s),
        host.count("."), host.count("-"), sum(map(str.isdigit, host)),
        # statistics
        n_digits / n if n else 0.0,
        n_letters / n if n else 0.0,
        (n - n_digits - n_letters) / n if n else 0.0,
        _entropy(u),
        _entropy(host),
        max((len(t) for t in tokens), default=0),
        (sum(len(t) for t in tokens) / len(tokens)) if tokens else 0.0,
        max((len(m.group(0)) for m in _RUN_RE.finditer(u)), default=0),
        (sum(ch in _VOWELS for ch in host_letters) / len(host_letters)) if host_letters else 0.0,
        # host structure
        len(sub_labels),
        int(p.is_ip),
        int(p.port.isdigit()),
        int("xn--" in host),
        int("@" in u),
        int(any(lbl in COMMON_TLD_LABELS for lbl in sub_labels)),
        int("//" in path),
        int(bool(_EMBEDDED_URL_RE.search(path + "?" + query))),
        # lexical signals
        len(_KEYWORD_RE.findall(ul)),
        int(brand_hit),
        int(rd in SHORTENERS or host in SHORTENERS),
        int(p.suffix.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS if p.suffix else False),
        int(bool(_RISKY_EXT_RE.search(path))),
        int(".php" in path_l),
        int(".htm" in path_l),
    )


_ZERO_VECTOR = tuple(0 for _ in LEXICAL_FEATURES)


def _safe_tuple(url: object, already_normalized: bool = False) -> tuple:
    try:
        return _feature_tuple(parse_url(url, already_normalized=already_normalized))
    except Exception:  # never crash on garbage input
        return _ZERO_VECTOR


def extract_features(url: object) -> dict:
    """Lexical features of ONE raw URL (normalised internally).

    Returns a dict in ``LEXICAL_FEATURES`` order. Never raises.
    """
    return dict(zip(LEXICAL_FEATURES, _safe_tuple(url)))


def extract_features_batch(urls: Iterable, *, already_normalized: bool = False) -> pd.DataFrame:
    """Vectorised-ish version for a pandas Series / list.

    Uses the very same per-URL function as ``extract_features`` (so the values
    are identical), but computes each distinct URL only once.
    """
    s = pd.Series(list(urls) if not isinstance(urls, pd.Series) else urls, dtype=object)
    codes, uniques = pd.factorize(s, use_na_sentinel=False)   # NaN gets its own code
    rows = [_safe_tuple(u, already_normalized) for u in uniques]
    uniq = pd.DataFrame.from_records(rows, columns=list(LEXICAL_FEATURES))
    out = uniq.iloc[codes].reset_index(drop=True)
    out.index = s.index
    float_cols = ["digit_ratio", "letter_ratio", "special_char_ratio", "url_entropy",
                  "host_entropy", "avg_token_len", "host_vowel_ratio"]
    out = out.astype({c: "float64" for c in float_cols})
    # counts/flags never exceed the 2,000-char URL cap -> int32 halves the memory
    out = out.astype({c: "int32" for c in LEXICAL_FEATURES if c not in float_cols})
    return out


def url_parts_batch(urls: Iterable, *, already_normalized: bool = False) -> pd.DataFrame:
    """normalized url, host, registered_domain, group_key, tld for many URLs."""
    s = pd.Series(list(urls) if not isinstance(urls, pd.Series) else urls, dtype=object)
    codes, uniques = pd.factorize(s, use_na_sentinel=False)
    recs = []
    for u in uniques:
        p = parse_url(u, already_normalized=already_normalized)
        recs.append((p.normalized, p.host, p.registered_domain, p.group_key, p.tld, p.is_ip))
    df = pd.DataFrame.from_records(
        recs, columns=["url_normalized", "host", "registered_domain", "group_key", "tld", "is_ip"]
    ).iloc[codes].reset_index(drop=True)
    df.index = s.index
    return df


def keyword_presence(urls: Iterable[str]) -> pd.DataFrame:
    """0/1 matrix: does each SUSPICIOUS_KEYWORD occur in each (normalised) URL?"""
    s = pd.Series(list(urls) if not isinstance(urls, pd.Series) else urls).astype(str).str.lower()
    return pd.DataFrame({k: s.str.contains(k, regex=False).astype("int8") for k in SUSPICIOUS_KEYWORDS},
                        index=s.index)


# --------------------------------------------------------------------------- #
# Fitted transformer: lexical features + TLD target encoding
# --------------------------------------------------------------------------- #
class UrlFeatureExtractor:
    """Turns raw URLs into the model's feature matrix.

    ``tld_malicious_rate`` is an m-estimate (smoothed) target encoding:

        rate(tld) = (n_malicious(tld) + m * prior) / (n(tld) + m)

    where ``prior`` is the overall malicious rate of the TRAINING set. TLDs with
    few samples are pulled towards the prior; unseen TLDs get the prior.

    * ``fit(urls, y)`` learns the mapping from the training set only.
    * ``fit_transform(urls, y, groups)`` additionally returns *out-of-fold*
      encodings for the training rows (GroupKFold by registered domain), so a
      row's own label never leaks into its own feature during training.
    * ``transform(urls)`` (val / test / API) uses the full training mapping.
    """

    def __init__(self, m: float = 50.0, n_splits: int = 5, random_state: int = 42,
                 feature_names: Sequence[str] | None = None):
        self.m = m
        self.n_splits = n_splits
        self.random_state = random_state
        self.feature_names = list(feature_names) if feature_names else (
            list(LEXICAL_FEATURES) + list(ENCODED_FEATURES))

    # -- target encoding helpers ------------------------------------------- #
    @staticmethod
    def _tlds(urls: Iterable, already_normalized: bool) -> pd.Series:
        return url_parts_batch(urls, already_normalized=already_normalized)["tld"]

    def _rates(self, tld: pd.Series, y: np.ndarray) -> tuple[dict, float]:
        prior = float(np.mean(y))
        g = pd.DataFrame({"tld": tld.to_numpy(), "y": y}).groupby("tld")["y"].agg(["sum", "count"])
        rates = (g["sum"] + self.m * prior) / (g["count"] + self.m)
        return rates.to_dict(), prior

    def fit(self, urls: Iterable, y: Iterable, *, already_normalized: bool = False):
        y = np.asarray(y, dtype=float)
        tld = self._tlds(urls, already_normalized)
        self.tld_rates_, self.prior_ = self._rates(tld, y)
        self.tld_counts_ = tld.value_counts().to_dict()
        return self

    def encode_tld(self, tld: pd.Series) -> np.ndarray:
        return tld.map(self.tld_rates_).fillna(self.prior_).to_numpy(dtype=float)

    def tld_feature(self, urls: Iterable, *, already_normalized: bool = False) -> np.ndarray:
        """tld_malicious_rate from the fitted (full-train) mapping: val / test / API."""
        return self.encode_tld(self._tlds(urls, already_normalized).reset_index(drop=True))

    @staticmethod
    def group_folds(groups: Iterable, n_splits: int, random_state: int) -> np.ndarray:
        """Fold id per row such that every group lies in exactly one fold.

        Groups are shuffled (seeded) and the shuffled list is cut into
        ``n_splits`` chunks of roughly equal ROW count. O(n), unlike
        scikit-learn's shuffled GroupKFold, which took minutes on ~225k groups.
        """
        codes, uniques = pd.factorize(pd.Series(list(groups) if not isinstance(groups, pd.Series)
                                                else groups, dtype=object))
        sizes = np.bincount(codes, minlength=len(uniques))
        order = np.random.default_rng(random_state).permutation(len(uniques))
        cum_before = np.cumsum(sizes[order]) - sizes[order]
        fold_of_group = np.empty(len(uniques), dtype=int)
        fold_of_group[order] = np.minimum((cum_before * n_splits) // sizes.sum(), n_splits - 1)
        return fold_of_group[codes]

    def oof_tld_feature(self, urls: Iterable, y: Iterable, groups: Iterable | None = None,
                        *, already_normalized: bool = False) -> np.ndarray:
        """Out-of-fold tld_malicious_rate for TRAINING rows: each fold is encoded
        with rates computed on the other folds (grouped by domain if given)."""
        y = np.asarray(y, dtype=float)
        tld = self._tlds(urls, already_normalized).reset_index(drop=True)
        if groups is None:   # each row is its own group
            groups = np.arange(len(tld))
        fold = self.group_folds(groups, self.n_splits, self.random_state)
        oof = np.empty(len(tld), dtype=float)
        for k in range(self.n_splits):
            va = fold == k
            rates, prior = self._rates(tld[~va], y[~va])
            oof[va] = tld[va].map(rates).fillna(prior).to_numpy(dtype=float)
        return oof

    def fit_transform(self, urls: Iterable, y: Iterable, groups: Iterable | None = None,
                      *, already_normalized: bool = False) -> pd.DataFrame:
        urls = pd.Series(list(urls) if not isinstance(urls, pd.Series) else urls)
        self.fit(urls, y, already_normalized=already_normalized)
        X = extract_features_batch(urls, already_normalized=already_normalized)
        X["tld_malicious_rate"] = self.oof_tld_feature(urls, y, groups,
                                                       already_normalized=already_normalized)
        X.index = urls.index
        return X[self.feature_names]

    def transform(self, urls: Iterable, *, already_normalized: bool = False) -> pd.DataFrame:
        urls = pd.Series(list(urls) if not isinstance(urls, pd.Series) else urls)
        X = extract_features_batch(urls, already_normalized=already_normalized)
        X["tld_malicious_rate"] = self.tld_feature(urls, already_normalized=already_normalized)
        X.index = urls.index
        return X[self.feature_names]

    def transform_one(self, url: str) -> pd.DataFrame:
        """Convenience for the API: one URL -> 1-row DataFrame in model order."""
        return self.transform([url])

    def __repr__(self) -> str:  # pragma: no cover
        fitted = hasattr(self, "tld_rates_")
        return (f"UrlFeatureExtractor(m={self.m}, n_features={len(self.feature_names)}, "
                f"fitted={fitted}{f', n_tlds={len(self.tld_rates_)}' if fitted else ''})")
