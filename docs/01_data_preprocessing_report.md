# Step 1 Report: Data Collection, Preprocessing and EDA

**Project:** Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)
**Notebook:** `notebooks/01_data_preprocessing_eda.ipynb` (executed). HTML copy: `reports/01_data_preprocessing_eda.html`
**Code:** `src/data.py` (loading, cleaning, split), `src/features.py` (normalization + features; reused by the API)

Every number in this report was produced by running the notebook. Figures are in `reports/figures/`.

---

## 1. Data sources

| # | Dataset | Rows (raw) | Classes | Role |
|---|---|---|---|---|
| 1 | Malicious URLs Dataset (Kaggle, sid321axn; built from ISCX-URL-2016, PhishTank, PhishStorm, malware domain lists) | 651,097 | benign 428,101 · defacement 96,457 · phishing 94,019 · malware 32,520 | train / val / test |
| 2 | PhiUSIIL Phishing URL Dataset (UCI #967, Prasad & Chandra 2024) | 235,795 | legitimate 134,850 · phishing 100,945 | train / val / test |
| 3 | OpenPhish public feed, snapshot of 2026-11-24 14:23:18 UTC | 300 URLs | live phishing | **unseen test set for Step 2 only, never used for training** |

All files are downloaded by `scripts/download_data.py`, which verifies size and SHA-256 and skips
files that already match.

**Unified schema:**
- `url_original`
- `type`: benign / defacement / phishing / malware
- `label`: 0 = benign, 1 = malicious (phishing + malware + defacement)
- `source`

### Loading issues and how they were solved

| Issue | Evidence | Solution |
|---|---|---|
| Kaggle CSV cannot be read with `pd.read_csv` | `ParserError: Expected 2 fields in line 4028, saw 8`. 903 URLs contain unquoted commas and 40 lines are wrapped in quotes | Parse line by line. The label is the last field: `url, label = line.rsplit(",", 1)`. Strip quotes/whitespace, lowercase the label (`Defacement` → `defacement`, `phishing"` → `phishing`) |
| Kaggle row count differs from the published 651,191 | 651,097 rows parsed | 94 rows (0.01%) are absent from this version. Documented, not recreated |
| PhiUSIIL label meaning is inverted | `label = 1` is legitimate in PhiUSIIL | Explicit mapping 1 → benign, 0 → phishing |
| PhiUSIIL mirror returns a Git LFS pointer (133 bytes) instead of the CSV | Checksum mismatch | Download script detects LFS pointers and falls back to the LFS media URL |
| A download timed out on the slow connection | `The read operation timed out` | Retries with HTTP Range resume |

### Why we use only URL + label from PhiUSIIL

PhiUSIIL ships 54 pre-computed columns, and we ignore all of them, for three reasons:

1. **Most need the web page** (`LineOfCode`, `HasTitle`, `NoOfImage`, `HasPasswordField`, …). Our
   API only sees the URL string, so it could never compute them.
2. **Some are near-leaky.** `URLSimilarityIndex` equals 100 for 100% of legitimate URLs but only
   0.78% of phishing URLs, which gives a single-column ROC-AUC of 0.996.
3. **`IsHTTPS` is a collection artefact.** It is 1 for 100% of legitimate URLs vs 49.2% of
   phishing URLs.

We recompute all features with our own code, so both sources get one consistent feature
definition.

## 2. Cleaning: the data funnel

| Stage | Rows | Removed | Kaggle | PhiUSIIL | Note |
|---|---:|---:|---:|---:|---|
| 0. raw rows loaded | 886,892 | 0 | 651,097 | 235,795 | |
| 1. repair scraping artefacts | 886,892 | 0 | 651,097 | 235,795 | 13,312 URLs modified, no rows removed |
| 2. drop empty / whitespace URLs | 886,892 | 0 | 651,097 | 235,795 | none found |
| 3. drop non-printable / garbage URLs | 886,852 | 40 | 651,057 | 235,795 | mojibake, control chars |
| 4. drop URLs > 2,000 chars | 886,842 | 10 | 651,055 | 235,787 | 8 phishing, 2 benign |
| 5. drop rows whose host cannot be parsed | 886,832 | 10 | 651,045 | 235,787 | redaction placeholders, relative paths, retired TLD |
| 6. drop URLs with conflicting labels (all copies) | 877,855 | 8,977 | 642,171 | 235,684 | 4,194 normalized URLs |
| 7. drop duplicates within a source | 857,818 | 20,037 | 626,428 | 231,390 | 11,948 exact + 8,089 after normalization |
| 8. drop duplicates across sources | **856,600** | 1,218 | 626,428 | 230,172 | kept the Kaggle copy |

**Missing values:** none of the 4 raw columns had a NaN or an empty string. After feature
extraction, the 48 lexical features were also checked: **0 NaN and 0 inf**, asserted in code.

### 2.1 Scraping artefacts (repaired, rows kept)

| Artefact | benign | defacement | phishing | malware | Why it matters |
|---|---:|---:|---:|---:|---|
| URL wrapped in `'...'` | 3,565 | 0 | 336 | 0 | export artefact |
| HTML-escaped `&amp;` | 7,123 | 0 | 4,122 | 5 | a browser sends `&`, never `&amp;` |
| octal byte escapes (`\321`) | 0 | 386 | 0 | 0 | converted to standard `%D1` |
| escaped percent `\%20` | 3,227 | 0 | 179 | 0 | converted to `%20` |

None of these artefacts is spread evenly across classes, so each could become a shortcut. For
example, `&amp;` never occurs in defacement URLs. Repairing them makes every string look like what
Chrome would send.

### 2.2 Duplicates and conflicting labels

* **4,194 normalized URLs had conflicting labels.** All 8,977 of their rows were dropped; we did not
  guess a label.
  * 4,187 are benign-vs-malicious conflicts and 7 are phishing-vs-malware conflicts.
  * **4,132 of them are inside Kaggle**, where the *same* URL is labelled **phishing when written
    with `http://`** and **benign when written without a scheme**. Example:
    `0000502.rcomhost.com/secure-listings-redirect/products/ebaymotors/pages/SignIn.php?...`
  * Only 6 conflicts are byte-identical strings. This is direct evidence of the formatting bias
    described in section 3.
* **20,037 duplicates within a source** were removed. 11,948 were exact copies, mostly Kaggle malware
  (8,875) and defacement (1,149). 8,089 became duplicates only after normalization; for example,
  3,790 PhiUSIIL phishing URLs were listed both as `http://` and `https://`.
* **1,218 URLs appeared in both sources** (1,166 benign, 52 phishing). We kept the Kaggle copy.

### 2.3 Garbage and unparseable hosts

* **40 non-printable URLs.** Mostly Cyrillic page names decoded as Thai characters (24 defacement
  URLs on `rus-master.com`).
* **10 unparseable hosts:**
  * 5 malware entries are the dataset's own redaction placeholders
    (`c...content-available-to-author-only...e.org`);
  * 3 are relative paths without a host (`bin/webscr?cmd=_login-`);
  * 2 use the retired `.an` TLD.
* *Issue found and fixed:* the first host rule also removed **175 legitimate URLs** whose host is
  itself a public suffix (`www.gov.uk`, `www.nhs.uk`). Inspecting the dropped examples revealed
  this, and the rule was corrected.

### 2.4 Final class balance

| | benign | defacement | phishing | malware | total |
|---|---:|---:|---:|---:|---:|
| Kaggle | 420,448 | 95,284 | 87,116 | 23,580 | 626,428 |
| PhiUSIIL | 133,630 | 0 | 96,542 | 0 | 230,172 |
| **binary** | **554,078 (64.7%)** | | **302,522 malicious (35.3%)** | | **856,600** |

The imbalance ratio is **1.83 : 1** (benign : malicious). We don't resample in this step; Step 2
compares `class_weight="balanced"` against no weighting. Figure: `01_class_distribution.png`.

## 3. The bias discovery and fix (the most important part of Step 1)

### 3.1 What we found

How a URL is written in our data depends on **which list it came from**, not on whether it is
malicious. Rates are measured on the cleaned rows (figure `02_bias_scheme_www_before_after.png`):

| source · class | starts with a scheme | host starts with `www.` |
|---|---:|---:|
| Kaggle · benign | 8.3% | 3.0% |
| Kaggle · defacement | 100.0% | 69.6% |
| Kaggle · phishing | 20.7% | 40.5% |
| Kaggle · malware | 94.9% | 3.5% |
| PhiUSIIL · legitimate | **100.0%** | **100.0%** |
| PhiUSIIL · phishing | 100.0% | 42.1% |

The same shortcuts measured on the *raw* Kaggle file (before cleaning) match the figures measured
before the project started: a scheme is present in 100% of defacement, 96.3% of malware and 8.3%
of benign URLs.

| scope | benign with a path | malicious with a path | one-flag AUC of `has_path` |
|---|---:|---:|---:|
| Kaggle only | 87.7% | 88.2% | 0.503 |
| PhiUSIIL only | **0.0%** | 26.8% | **0.634** |
| merged | 66.5% | 68.6% | 0.510 |

A naive model would learn the following shortcuts:

* **"has `http://` → malicious"**: one-flag ROC-AUC **0.788** on Kaggle;
* **"has `www.` → malicious"** on Kaggle (AUC 0.734), but **"has `www.` → benign"** on PhiUSIIL
  (AUC 0.210, i.e. the reverse);
* **"has a path → malicious"** on PhiUSIIL (AUC 0.634).

Chrome always sends full URLs such as `https://www.google.com/search?q=x`, so a model like this
would flag Google on demo day. The 4,132 Kaggle URLs that are "phishing with a scheme, benign
without one" (section 2.2) show that this bias even reaches the labels.

### 3.2 The fix

`normalize_url()` in `src/features.py` (the API reuses it):

1. strip whitespace and drop the `#fragment`;
2. remove any `xxx://` scheme prefix;
3. lowercase the host but **not** the path;
4. remove leading `www.`/`www2.`/… (never the last real label: `www.com` stays);
5. remove the trailing `/`;
6. keep the port, path and query.

**No feature is ever created for the scheme, https or www.**

### 3.3 Proof that the shortcut is gone

* After normalization the scheme and `www.`-host rates are **0.0% in every class**, and every
  one-flag AUC is **exactly 0.500**.
* **Merging** the two sources cancels the path shortcut: "has a path" is 66.5% of benign vs 68.6%
  of malicious URLs, AUC **0.510** (figure `03_has_path_by_source_before_after_merge.png`).
* `https://www.google.com/search?q=x` and `google.com/search?q=x` now produce identical
  features.

## 4. Feature engineering

48 lexical features plus 1 encoded feature are computed on the normalized URL. Design choices:

* **Pure functions, no network.** `tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)` uses
  only the bundled Public Suffix List.
* **Never crashes.** Garbage input (IPv6, ports, `user:pass@`, unicode, punycode, missing host)
  returns a valid vector.
* **One code path.** `extract_features(url)` (used by the API) and `extract_features_batch(series)`
  run the same per-URL function. The notebook asserts identical output on 5,000 random URLs.
* **Speed.** 856,600 URLs × 48 features take **36.6 s** in a single process (~23,400 URLs/s) in
  the final run. Across our three runs the time was 36–44 s.
* **Unit tests.** `tests/test_features.py` passes **53 tests**.

All 49 candidate features (48 lexical + 1 encoded). 6 are later removed as redundant (section 7), so the model uses **43**.

| # | feature | group | what it measures | why it can signal maliciousness | in final model |
|---|---|---|---|---|---|
| 1 | `url_len` | length | characters in the normalised URL | phishing URLs pad the URL to hide the real domain | yes |
| 2 | `host_len` | length | characters in the host name | long hosts stack fake subdomains (paypal.com.x.y.tk) | yes |
| 3 | `path_len` | length | characters in the path | deep or random paths are typical of compromised sites / kits | yes |
| 4 | `query_len` | length | characters in the query string | long queries carry tracking ids, redirects or encoded payloads | yes |
| 5 | `registered_domain_len` | length | length of the registered domain (example.co.uk) | throw-away domains are often long or random | yes |
| 6 | `tld_len` | length | length of the public suffix | new gTLDs (.online, .support) are longer than .com / .in | yes |
| 7 | `num_dots` | count | '.' in URL | many dots = many subdomains or file-like names | yes |
| 8 | `num_hyphens` | count | '-' in URL | hyphenated look-alike domains (secure-paypal-login) | yes |
| 9 | `num_underscores` | count | '_' in URL | unusual in hosts; common in kit file names | yes |
| 10 | `num_slashes` | count | '/' in URL | path depth | yes |
| 11 | `num_question_marks` | count | '?' in URL | more than one '?' hints at an embedded URL | yes |
| 12 | `num_equals` | count | '=' in URL | number of parameter assignments | dropped (twin of `num_query_params`) |
| 13 | `num_ampersands` | count | '&' in URL | number of extra parameters | dropped (twin of `num_query_params`) |
| 14 | `num_at` | count | '@' in URL | '@' makes browsers ignore everything before it | yes |
| 15 | `num_percent` | count | '%' in URL | percent-encoding is used to obfuscate | yes |
| 16 | `num_tilde` | count | '~' in URL | user home directories on shared hosting | yes |
| 17 | `num_digits` | count | digits in URL | random ids, IPs, generated names | yes |
| 18 | `num_letters` | count | letters in URL | size of the alphabetic part | dropped (twin of `url_len`) |
| 19 | `num_other_special` | count | other non-alphanumeric chars (; , + ! * ...) | rare in normal URLs, common in obfuscation | yes |
| 20 | `num_query_params` | count | parameters in the query | phishing kits pass victim data in parameters | yes |
| 21 | `num_path_segments` | count | non-empty '/'-separated path parts | path depth | dropped (twin of `num_slashes`) |
| 22 | `host_num_dots` | count | '.' in host | subdomain depth | yes |
| 23 | `host_num_hyphens` | count | '-' in host | look-alike hosts | yes |
| 24 | `host_num_digits` | count | digits in host | generated / random hosts | yes |
| 25 | `digit_ratio` | statistic | digits / URL length | machine-generated URLs are digit-heavy | dropped (twin of `letter_ratio`) |
| 26 | `letter_ratio` | statistic | letters / URL length | human-readable URLs are letter-heavy | yes |
| 27 | `special_char_ratio` | statistic | non-alphanumeric chars / URL length | obfuscation and long queries | yes |
| 28 | `url_entropy` | statistic | Shannon entropy of the URL (bits/char) | random strings have high entropy | yes |
| 29 | `host_entropy` | statistic | Shannon entropy of the host | algorithmically generated domains (DGA) | yes |
| 30 | `longest_token_len` | statistic | longest alphanumeric token | long random tokens / hashes | yes |
| 31 | `avg_token_len` | statistic | mean alphanumeric token length | natural words are short | yes |
| 32 | `max_consecutive_repeated_char` | statistic | longest run of one repeated character | padding tricks (----, 0000) | yes |
| 33 | `host_vowel_ratio` | statistic | vowels / letters in host | random hosts have unnatural vowel ratios | yes |
| 34 | `num_subdomains` | host | labels before the registered domain (www removed) | brand names hidden in subdomains | dropped (twin of `host_num_dots`) |
| 35 | `has_ip_host` | host | host is an IPv4 (dotted/hex/decimal) or IPv6 address | no domain name = no accountability | yes |
| 36 | `has_port` | host | explicit port number | non-standard ports are rare for real sites | yes |
| 37 | `has_punycode` | host | host contains 'xn--' (internationalised) | homograph attacks (pаypal with Cyrillic a) | yes |
| 38 | `has_at_symbol` | host | '@' present | user-info trick http://paypal.com@evil.net | yes |
| 39 | `tld_in_subdomain` | host | a label like com/net/org inside the subdomain | paypal.com.evil.tk pattern | yes |
| 40 | `double_slash_in_path` | host | '//' inside the path | open-redirect style URLs | yes |
| 41 | `embedded_url` | host | http(s): or www. inside path/query | redirect chains to another site | yes |
| 42 | `suspicious_keyword_count` | lexical | occurrences of words like login, verify, account | social-engineering vocabulary | yes |
| 43 | `brand_in_non_registered_part` | lexical | a well-known brand in subdomain/path while the domain is not that brand | impersonation (apple.id-verify.xyz/apple) | yes |
| 44 | `is_shortener` | lexical | domain is a URL shortener | hides the real destination | yes |
| 45 | `suspicious_tld` | lexical | TLD on a published most-abused list | cheap / free TLDs are used for throw-away domains | yes |
| 46 | `risky_file_extension` | lexical | path ends in .exe .apk .zip .js ... | direct malware download | yes |
| 47 | `has_php` | lexical | '.php' in path | phishing kits / compromised CMS pages are mostly PHP | yes |
| 48 | `has_html` | lexical | '.htm(l)' in path | static phishing pages | yes |
| 49 | `tld_malicious_rate` | encoded | smoothed share of malicious URLs with this TLD (train only) | data-driven TLD reputation | yes |

## 5. Train / validation / test split

* **Grouped by registered domain** with `StratifiedGroupKFold` (20 folds, `random_state=42`):
  14 folds go to train, 3 to val and 3 to test. Stratification is by source × type. IP hosts use
  the IP itself as the group.
* **Why grouping:** with a random split, **65.8% of test URLs** would come from a domain already
  seen in training (wikipedia.org alone has 13,422 URLs). Test scores would then measure domain
  memorization, not generalization to new websites, which is what the Chrome extension faces.
* **Result:** 321,423 domains, **0 shared between splits** (asserted in code).

| split | rows | % | domains | malicious % | defacement % | phishing % | malware % |
|---|---:|---:|---:|---:|---:|---:|---:|
| train | 591,470 | 69.05 | 225,303 | 35.63 | 11.28 | 21.79 | 2.56 |
| val | 132,498 | 15.47 | 47,936 | 35.24 | 10.79 | 20.62 | 3.83 |
| test | 132,632 | 15.48 | 48,184 | 33.98 | 10.78 | 20.68 | 2.52 |

* **Split before encoding/scaling.** The assignment lists "encode → scale → split", but the TLD
  encoding uses labels and the scaler learns means. Fitting either on all the data would leak
  test information, so we split first.

## 6. Encoding categorical variables

* **TLD → `tld_malicious_rate`.** There are 1,386 distinct TLDs in train, too many for one-hot
  encoding. We use m-estimate target encoding:
  rate = (n_malicious + m·p) / (n + m), with m = 50 and p = 0.3563, the training malicious share.
  * Large TLDs are unchanged: `.com` 0.2482 → 0.2482, `.de` 0.7544 → 0.7528.
  * A TLD seen once (and malicious that one time) gets 0.369 instead of 1.0.
  * Unseen TLDs get p. That affects 211 validation rows and 214 test rows (0.16%).
* **No leakage.**
  * The encoder is fitted on the **training split only**.
  * Training rows get **out-of-fold** encodings: 5 folds grouped by domain, so a row's own label
    never feeds its own feature.
  * Validation, test and the API use the full training mapping.
* **Saved for the API.** `UrlFeatureExtractor` is saved to `models/feature_extractor.joblib`. From a
  raw URL it reproduces exactly the notebook's feature values, which is asserted on 3,000
  validation URLs and 2,000 test URLs.
* **`type` label encoding** (optional multi-class view): benign 0, defacement 1, malware 2,
  phishing 3, saved to `models/type_label_encoder.joblib`.
* `source` is **never** a feature. It would be a pure shortcut.

## 7. Redundancy check and final feature list

Computed on train. For each pair with |r| > 0.9, the feature with the lower mutual information is
dropped:

| dropped | kept | r | MI dropped | MI kept |
|---|---|---:|---:|---:|
| num_equals | num_query_params | 0.987 | 0.0346 | 0.0360 |
| num_ampersands | num_query_params | 0.971 | 0.0353 | 0.0360 |
| num_path_segments | num_slashes | 0.962 | 0.0191 | 0.0216 |
| num_letters | url_len | 0.961 | 0.0167 | 0.0206 |
| digit_ratio | letter_ratio | -0.943 | 0.0608 | 0.0614 |
| num_subdomains | host_num_dots | 0.924 | 0.0079 | 0.0308 |

**43 features remain** and the largest remaining |r| is 0.860. Their order is fixed in
`data/processed/feature_list.json`, and the API must use exactly this order. The extractor
enforces it.

## 8. Scaling

* A `StandardScaler` is fitted on train only and saved to `models/scaler.joblib`.
* After scaling, train has mean 0 and std 1. Validation is close but not exact (`url_len`: mean
  0.018, std 0.976), which shows that no validation information leaked into the scaler.
* Tree models do not need scaling. Logistic Regression, KNN and Naive Bayes in Step 2 will use the
  scaler inside a scikit-learn `Pipeline`. The parquet files store **unscaled** values.
* The class imbalance ratio (benign : malicious) is **1.81 : 1 in train**, 1.84 in val and 1.94 in
  test. We do not resample now; Step 2 compares `class_weight="balanced"` against no weighting.

## 9. Key EDA findings (training split)

| # | Figure | Finding |
|---|---|---|
| 1 | `01_class_distribution.png` | 856,600 URLs: 64.7% benign / 35.3% malicious. Malware is only 2.8% of rows |
| 2 | `02_bias_scheme_www_before_after.png`, `03_has_path_by_source_before_after_merge.png` | The scheme/www/path shortcuts exist in the raw data (one-flag AUC up to 0.788) and are gone after normalization and merging (0.500 / 0.510) |
| 3 | `04_url_and_host_length_by_class.png` | Defacement URLs are the longest (median 71 chars, long CMS queries). Phishing URLs are *not* longer than benign after normalization (27 vs 35). Phishing has the longest hosts (median 17, p75 24); malware the shortest (13, IP hosts) |
| 4 | `05_top20_tlds_by_count.png`, `06_tld_malicious_rate.png` | `.com` = 57.0% of URLs, 25% malicious. Freenom TLDs (.cf .ml .gq .ga), .top, .xyz and IP hosts are 99–100% malicious. .gov.uk, .gc.ca and .qc.ca are 1–2%. The cited `suspicious_tld` list: 93.8% malicious vs 34.9% for the rest |
| 5 | `07_key_features_by_class.png` | Malware: median digit ratio 0.395 and lowest host entropy (2.82; IP:port URLs, e.g. Mozi botnet). Phishing: highest host entropy (3.46), the only class with a subdomain at p75 |
| 6 | `08_binary_flags_malicious_rate.png` | IP host 99.8% malicious, port 97.0%, suspicious TLD 93.8%, punycode 83.6%, risky extension 82.5%, shortener 78.9%. All are rare (≤ 1.7% of URLs). The brand / TLD-in-subdomain flags are weak (40–42%) because of label noise |
| 7 | `09_suspicious_keywords.png` | `wallet` 19×, `invoice` 15.6×, `verify` 10.3× more frequent in malicious URLs, but `login` is slightly more common in benign URLs, and `webscr` is 30× more common in *benign* (label noise) |
| 8 | `10_correlation_heatmap.png` | 7 pairs with \|r\| > 0.9, in 5 "counting the same thing" groups. 6 features dropped |
| 9 | `11_feature_relevance_mi_pointbiserial.png` | `tld_malicious_rate` leads (MI 0.130, r = +0.42), then host_entropy, tld_len, letter_ratio, digit_ratio, path_len. All MI ≤ 0.13, so no single feature solves the task |
| 10 | `12_top_tokens_log_odds.png` | Malicious tokens: free hosting (firebaseapp, weeblysite, repl, godaddysites), botnets (mozi, sbidiot), Apple-ID lures, Joomla event pages. Benign tokens: imdb, espn, torrent sites |
| 11 | `13_defacement_deep_dive.png` | Defacement = hacked Joomla sites: 52.0% `index.php`, 41.3% `option=com_` (≤ 1.6% in every other class). 1,486 domains for 66,700 URLs (median 37 per domain, crawl cap ≈ 102). The grouped split is essential, and there is a risk of false positives on legitimate Joomla sites |

**Top 10 features by mutual information:**

| rank | feature | MI | in final model? |
|---:|---|---:|---|
| 1 | tld_malicious_rate | 0.1304 | yes |
| 2 | host_entropy | 0.0684 | yes |
| 3 | tld_len | 0.0677 | yes |
| 4 | letter_ratio | 0.0614 | yes |
| 5 | digit_ratio | 0.0608 | no (twin of letter_ratio) |
| 6 | path_len | 0.0566 | yes |
| 7 | num_dots | 0.0476 | yes |
| 8 | url_entropy | 0.0451 | yes |
| 9 | host_vowel_ratio | 0.0406 | yes |
| 10 | host_num_digits | 0.0406 | yes |

## 10. Issues encountered and how they were solved

| # | Issue | Solution |
|---|---|---|
| 1 | Kaggle CSV unreadable by `read_csv` (unquoted commas, quoted lines) | Line-by-line parser splitting on the last comma |
| 2 | PhiUSIIL mirror served a Git LFS pointer | Checksum caught it; script falls back to the LFS media URL |
| 3 | Very slow connection (~50 KB/s), one download timed out | Retries with HTTP Range resume; `--verify-only` mode so the notebook never needs the network |
| 4 | Source-dependent formatting (scheme, www, path) = shortcut learning | `normalize_url()`, no scheme/www features, merged sources. Proven by AUC 0.788 → 0.500 |
| 5 | Same URL labelled phishing with `http://` and benign without it (4,132 cases) | Conflicting URLs dropped entirely (no guessing) |
| 6 | Uneven scraping artefacts (`&amp;`, `\%`, octal escapes, wrapping quotes) | Repaired to what a browser sends (13,312 URLs) |
| 7 | Host rule wrongly dropped `www.gov.uk` / `www.nhs.uk` (175 URLs) | Rule corrected after inspecting dropped examples |
| 8 | Label noise in Kaggle (3,212 ietf.org pages "phishing"; 5,739 PayPal-phishing `webscr` URLs "benign") | Documented and quantified, not relabeled by hand. Grouped split limits its impact. To be revisited in Step 2/3 error analysis |
| 9 | Domain memorization: a random split would put 65.8% of test URLs on known domains | `StratifiedGroupKFold` by registered domain, 0 shared domains |
| 10 | scikit-learn's shuffled `GroupKFold` took ~26 min on 225k groups | Replaced by an O(n) seeded grouped fold assignment (≈ 6 s), unit-tested |
| 11 | PhiUSIIL pre-computed features need the web page or are near-leaky (AUC 0.996) | Only URL + label used |

## 11. Final dataset and outputs

| | value |
|---|---|
| clean URLs | **856,600** (554,078 benign / 302,522 malicious) |
| train / val / test | 591,470 / 132,498 / 132,632 (69.05 / 15.47 / 15.48 %) |
| registered domains | 321,423 (0 shared between splits) |
| features | 43 (42 lexical + `tld_malicious_rate`), unscaled in parquet |
| unseen fresh test set | OpenPhish snapshot, 300 URLs (`data/external/`) |

| file | content |
|---|---|
| `data/processed/urls_clean.csv` (+ `.zip`) | url_original, url_normalized, registered_domain, type, label, source, split |
| `data/processed/{train,val,test}.parquet` | 43 features + label + type + type_id + source + URLs + registered_domain |
| `data/processed/feature_list.json` | ordered feature names, dropped features with reasons, TLD prior |
| `models/feature_extractor.joblib` | fitted `UrlFeatureExtractor` (normalization + features + TLD encoding) |
| `models/scaler.joblib` | `StandardScaler` fitted on train |
| `models/type_label_encoder.joblib` | `LabelEncoder` for the 4 types |
| `reports/figures/01–13_*.png` | all EDA figures (dpi 150) |

**Next (Step 2):** compare 13 models on these features, select the best model, tune Random Forest,
evaluate on the test set and the OpenPhish snapshot.

