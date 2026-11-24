"""Loading, cleaning, de-duplication and splitting of the raw URL datasets.

Every function here is deterministic and records what it did, so the notebook
and the report can show a "data funnel" (rows kept at each stage).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from .config import (KAGGLE_FILE, KAGGLE_PUBLISHED_ROWS, MAX_URL_LEN, PHIUSIIL_FILE,
                     RANDOM_STATE, TYPE_TO_LABEL)
from .features import parse_url

UNIFIED_COLUMNS = ["url_original", "type", "label", "source"]


# --------------------------------------------------------------------------- #
# 1. Loading
# --------------------------------------------------------------------------- #
def load_kaggle(path: Path = KAGGLE_FILE) -> tuple[pd.DataFrame, dict]:
    """Parse malicious_phish.csv line by line.

    ``pd.read_csv`` fails on this file: 903 URLs contain unquoted commas and 40
    lines are wrapped in double quotes as a whole. Since the label is always
    the LAST field, we split each line on its last comma.
    """
    # decode bytes ourselves: read_text() would also treat a lone "\r" inside a
    # URL as a line break and silently split a row in two
    text = Path(path).read_bytes().decode("utf-8")
    lines = text.split("\n")
    header = lines[0].rstrip("\r")
    body = [ln.rstrip("\r") for ln in lines[1:]]
    body = [ln for ln in body if ln != ""]
    urls, labels, raw_labels, no_comma = [], [], [], 0
    commas_in_url = quoted_lines = 0
    for ln in body:
        if "," not in ln:
            no_comma += 1
            continue
        url, lab = ln.rsplit(",", 1)
        if ln.startswith('"') or lab.endswith('"'):
            quoted_lines += 1
        url = url.strip().strip('"').strip()
        raw_labels.append(lab)
        lab = lab.strip().strip('"').strip().lower()
        if "," in url:
            commas_in_url += 1
        urls.append(url)
        labels.append(lab)
    df = pd.DataFrame({"url_original": urls, "type": labels})
    df["label"] = df["type"].map(TYPE_TO_LABEL)
    df["source"] = "kaggle_malicious_phish"
    info = {
        "header": header,
        "lines_in_file": len(body),
        "rows_parsed": len(df),
        "lines_without_comma": no_comma,
        "urls_containing_commas": commas_in_url,
        "lines_wrapped_in_quotes": quoted_lines,
        "raw_label_spellings": pd.Series(raw_labels).value_counts().to_dict(),
        "published_rows": KAGGLE_PUBLISHED_ROWS,
        "missing_vs_published": KAGGLE_PUBLISHED_ROWS - len(df),
    }
    unknown = set(df["type"]) - set(TYPE_TO_LABEL)
    if unknown:
        raise ValueError(f"unexpected Kaggle labels: {unknown}")
    return df[UNIFIED_COLUMNS], info


def load_phiusiil(path: Path = PHIUSIIL_FILE) -> tuple[pd.DataFrame, dict]:
    """Load ONLY the URL and label columns of PhiUSIIL.

    In PhiUSIIL ``label = 1`` means LEGITIMATE and ``0`` means PHISHING, the
    opposite of our convention, so we map it explicitly.
    """
    all_cols = pd.read_csv(path, nrows=0).columns.tolist()
    df = pd.read_csv(path, usecols=["URL", "label"], dtype={"URL": "string"})
    info = {
        "n_columns_in_file": len(all_cols),
        "columns_ignored": [c for c in all_cols if c not in ("URL", "label")],
        "rows": len(df),
        "raw_label_counts": df["label"].value_counts().sort_index().to_dict(),
        "missing_url": int(df["URL"].isna().sum()),
        "missing_label": int(df["label"].isna().sum()),
    }
    out = pd.DataFrame({
        "url_original": df["URL"].fillna("").astype(str).str.strip(),
        "type": df["label"].map({1: "benign", 0: "phishing"}),
    })
    if out["type"].isna().any():
        raise ValueError("unexpected PhiUSIIL label values")
    out["label"] = out["type"].map(TYPE_TO_LABEL)
    out["source"] = "phiusiil"
    return out[UNIFIED_COLUMNS], info


def load_all() -> tuple[pd.DataFrame, dict]:
    k, kinfo = load_kaggle()
    p, pinfo = load_phiusiil()
    df = pd.concat([k, p], ignore_index=True)
    return df, {"kaggle": kinfo, "phiusiil": pinfo}


# --------------------------------------------------------------------------- #
# 2. Repairing scraping artefacts (rows are kept, the URL string is fixed)
# --------------------------------------------------------------------------- #
_OCTAL_ESCAPE_RE = re.compile(r"\\([0-3][0-7]{2})")


def _strip_wrapping_single_quotes(u: str) -> str:
    return u[1:-1].strip() if len(u) >= 2 and u[0] == "'" and u[-1] == "'" else u


def _unescape_amp(u: str) -> str:
    for _ in range(3):              # handles double escaping "&amp;amp;"
        if "&amp;" not in u:
            break
        u = u.replace("&amp;", "&")
    return u


def _octal_to_percent(u: str) -> str:
    return _OCTAL_ESCAPE_RE.sub(lambda m: f"%{int(m.group(1), 8):02X}", u)


def _unescape_percent(u: str) -> str:
    return u.replace("\\%", "%")


#: (name, function, explanation) - applied in this order.
REPAIRS = [
    ("wrapping_single_quotes", _strip_wrapping_single_quotes,
     "URL wrapped in '...' (export artefact)"),
    ("html_escaped_ampersand", _unescape_amp,
     "'&amp;' is HTML escaping; a browser sends '&'"),
    ("octal_byte_escapes", _octal_to_percent,
     "UTF-8 bytes written as octal '\\321' -> standard '%D1'"),
    ("backslash_percent", _unescape_percent,
     "'\\%20' escaped percent -> '%20'"),
]


def repair_artifacts(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (df with column ``url`` = repaired URL, table of rows changed per repair/type)."""
    df = df.copy()
    url = df["url_original"].astype(str)
    stats = {}
    for name, fn, _ in REPAIRS:
        new = url.map(fn)
        changed = new != url
        stats[name] = df.loc[changed, "type"].value_counts()
        url = new
    df["url"] = url
    table = pd.DataFrame(stats).T.reindex(columns=["benign", "defacement", "phishing", "malware"]).fillna(0).astype(int)
    table["total"] = table.sum(axis=1)
    table["why"] = [why for _, _, why in REPAIRS]
    return df, table


# --------------------------------------------------------------------------- #
# 3. Cleaning with a data funnel
# --------------------------------------------------------------------------- #
_HOST_LABELS_RE = re.compile(r"^[a-z0-9_\-¡-￿]+(\.[a-z0-9_\-¡-￿]+)*$")


def is_printable_url(u: str) -> bool:
    """False for control characters, non-printing format chars and U+FFFD."""
    return u.isprintable() and "�" not in u


def host_problem(url_normalized: str) -> str:
    """'' if the host is usable, else a short reason.

    Note: a host that IS a public suffix (gov.uk, nhs.uk, ne.jp) is valid:
    www.gov.uk is a real site, so it is kept (its group key is the host).
    """
    p = parse_url(url_normalized, already_normalized=True)
    if not p.host:
        return "empty host"
    if p.is_ip:
        return ""
    if not _HOST_LABELS_RE.match(p.host):
        return "invalid characters"
    if "." not in p.host:
        return "single-label host"
    if not p.suffix:
        return "no public suffix"
    return ""


@dataclass
class Funnel:
    rows: list = field(default_factory=list)

    def add(self, stage: str, df: pd.DataFrame, note: str = "") -> None:
        prev = self.rows[-1]["rows"] if self.rows else len(df)
        counts = df["source"].value_counts()
        self.rows.append({
            "stage": stage,
            "rows": len(df),
            "removed": prev - len(df),
            "kaggle": int(counts.get("kaggle_malicious_phish", 0)),
            "phiusiil": int(counts.get("phiusiil", 0)),
            "note": note,
        })

    def table(self) -> pd.DataFrame:
        return pd.DataFrame(self.rows)


def clean(df: pd.DataFrame, max_len: int = MAX_URL_LEN) -> tuple[pd.DataFrame, Funnel, dict]:
    """Full cleaning pipeline. Input: output of ``load_all``."""
    from .features import normalize_url

    funnel = Funnel()
    details: dict = {}
    funnel.add("0. raw rows loaded", df)

    df, repair_table = repair_artifacts(df)
    details["repairs"] = repair_table
    funnel.add("1. repair scraping artefacts (no rows removed)", df,
               f"{int((df['url'] != df['url_original']).sum()):,} URLs modified")

    empty = df["url"].str.strip() == ""
    details["empty"] = int(empty.sum())
    df = df[~empty]
    funnel.add("2. drop empty / whitespace URLs", df)

    printable = df["url"].map(is_printable_url)
    details["non_printable_examples"] = df.loc[~printable, ["url", "type", "source"]].head(10)
    details["non_printable"] = int((~printable).sum())
    df = df[printable]
    funnel.add("3. drop non-printable / garbage URLs", df,
               "control chars, U+FFFD or other non-printing characters")

    too_long = df["url"].str.len() > max_len
    details["too_long"] = df.loc[too_long, "type"].value_counts().to_dict()
    df = df[~too_long]
    funnel.add(f"4. drop URLs longer than {max_len:,} chars", df)

    df = df.copy()
    df["url_normalized"] = df["url"].map(normalize_url)
    problem = df["url_normalized"].map(host_problem)
    bad = problem != ""
    details["host_problems"] = (df.loc[bad].groupby([problem[bad], "type"]).size()
                                .unstack(fill_value=0))
    details["host_problem_examples"] = df.loc[bad, ["url_original", "type", "source"]].assign(
        reason=problem[bad]).groupby("reason").head(3)
    df = df[~bad]
    funnel.add("5. drop rows whose host cannot be parsed", df,
               "empty host, invalid characters, no dot, or no public suffix")

    # --- de-duplication on the NORMALISED url -------------------------------- #
    n_types = df.groupby("url_normalized")["type"].transform("nunique")
    n_labels = df.groupby("url_normalized")["label"].transform("nunique")
    conflict = n_types > 1
    details["conflict_urls"] = int(df.loc[conflict, "url_normalized"].nunique())
    details["conflict_rows"] = int(conflict.sum())
    details["conflict_urls_binary"] = int(df.loc[n_labels > 1, "url_normalized"].nunique())
    details["conflict_urls_type_only"] = details["conflict_urls"] - details["conflict_urls_binary"]
    details["conflict_examples"] = (df.loc[conflict].sort_values("url_normalized")
                                    [["url_original", "url_normalized", "type", "source"]].head(12))
    details["conflict_type_pairs"] = (df.loc[conflict].groupby("url_normalized")["type"]
                                      .agg(lambda s: " + ".join(sorted(set(s)))).value_counts())
    short = df["source"].map({"kaggle_malicious_phish": "Kaggle", "phiusiil": "PhiUSIIL"})
    tag = (short + ":" + df["type"])[conflict]
    details["conflict_source_combinations"] = (
        tag.groupby(df.loc[conflict, "url_normalized"]).agg(lambda s: " | ".join(sorted(set(s))))
        .value_counts().rename("normalised URLs"))
    raw_variants = df.loc[conflict].groupby("url_normalized")["url"].nunique()
    details["conflict_raw_identical"] = int((raw_variants == 1).sum())
    df = df[~conflict]
    funnel.add("6. drop URLs with conflicting labels (all copies)", df)

    within = df.duplicated(["source", "url_normalized"], keep="first")
    exact = df.duplicated(["source", "url"], keep="first")
    details["dup_within_source"] = df.loc[within, "source"].value_counts().to_dict()
    details["dup_within_source_by_type"] = pd.DataFrame({
        "exact raw duplicates": df.loc[within & exact].groupby(["source", "type"]).size(),
        "duplicates only after normalisation": df.loc[within & ~exact].groupby(["source", "type"]).size(),
    }).fillna(0).astype(int)
    df = df[~within]
    funnel.add("7. drop duplicates within a source", df)

    across = df.duplicated("url_normalized", keep="first")   # Kaggle rows come first
    details["dup_across_sources"] = int(across.sum())
    details["dup_across_sources_by_type"] = df.loc[across, "type"].value_counts().to_dict()
    df = df[~across]
    funnel.add("8. drop duplicates across sources", df, "kept the Kaggle copy")

    return df.reset_index(drop=True), funnel, details


# --------------------------------------------------------------------------- #
# 4. Grouped, stratified train / val / test split
# --------------------------------------------------------------------------- #
def grouped_split(df: pd.DataFrame, group_col: str = "registered_domain",
                  strat_cols: tuple[str, ...] = ("source", "type"),
                  n_folds: int = 20, train_folds: int = 14, val_folds: int = 3,
                  random_state: int = RANDOM_STATE) -> pd.Series:
    """70/15/15 split where every registered domain lands in exactly ONE split.

    StratifiedGroupKFold cuts the data into 20 folds of ~5% that (a) never split
    a group and (b) keep the source x type mix similar. 14 folds -> train (70%),
    3 -> val (15%), 3 -> test (15%).
    """
    from sklearn.model_selection import StratifiedGroupKFold

    strat = df[strat_cols[0]].astype(str)
    for c in strat_cols[1:]:
        strat = strat + "|" + df[c].astype(str)
    sgkf = StratifiedGroupKFold(n_splits=n_folds, shuffle=True, random_state=random_state)
    fold = np.empty(len(df), dtype=int)
    for k, (_, idx) in enumerate(sgkf.split(np.zeros(len(df)), strat, groups=df[group_col])):
        fold[idx] = k
    split = np.where(fold < train_folds, "train",
                     np.where(fold < train_folds + val_folds, "val", "test"))
    return pd.Series(split, index=df.index, name="split")
