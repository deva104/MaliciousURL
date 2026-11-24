# Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)

**Final Project Report: Computational Intelligence (V Semester)**
**Team:** Devendra Harale, Shravani Vyaghrambare, Talha Shaikh, Shrutika Gaikwad
**Repository:** https://github.com/deva104/MaliciousURL · **Live API:** https://malicious-url-api.onrender.com

---

## Abstract

Phishing, malware and defaced websites reach users through links, and blocklists only know URLs
that have already been reported. We built a system that judges a URL **from its text alone**, fast
enough to check every page a user opens.

**Data.** We merged two public datasets (Kaggle *Malicious URLs*, UCI *PhiUSIIL*) into **856,600**
clean URLs.

**Shortcuts.** In the raw data, *how* a URL was written (with `http://`, with `www.`, with a path)
depended on which list it came from. A one-flag classifier using only the scheme reached ROC-AUC
0.788. We removed these shortcuts by normalising every URL, and proved they were gone (AUC 0.500).

**Features and evaluation.** We engineered 43 lexical features and compared **13 models** on a
train/validation/test split **grouped by registered domain**, so every test URL comes from a
website the model has never seen.

**Model.** After tuning and a deployability constraint (≤ 25 MB, ≤ 20 ms per URL), the deployed
model is a **Soft Voting ensemble of a tuned Random Forest, tuned XGBoost and LightGBM**. Its
threshold of 0.80 keeps false alarms at about 1%.

**Results.** On the untouched test set:
* **precision 0.966**, recall 0.462, F1 0.625, **false-positive rate 0.84%**, ROC-AUC 0.888;
* on live phishing from November 2026 (OpenPhish), recall **79.2%** overall, but only **22.0%** on
  never-seen domains.

**Split comparison.** A controlled experiment shows that the usual random split would have reported
F1 **0.80 instead of 0.73**, because 66% of random-test URLs come from websites already seen in
training.

**Deployment.** The model is served by a FastAPI service in Docker on Render (13.3 MB, ~14 ms per
URL, ~280 MB RAM) and used by a Manifest V3 Chrome extension, **URL Guard**.

---

## 1. Introduction and problem

A malicious URL leads to a phishing page that steals credentials or card data, to malware, or to a
hacked ("defaced") website. The scale is large:
* The **Anti-Phishing Working Group (APWG)** observed **1,003,924, 1,130,393, 892,494 and 853,244**
  phishing attacks in the four quarters of 2025, about **3.88 million** in one year [1].
* The **FBI's IC3** received **859,532** complaints in 2024, with reported losses of **US $16.6
  billion**. Phishing/spoofing was the most reported crime type, with **193,407** complaints [2].
* Attackers favour cheap or free domains. Interisle found that in November 2022 the free Freenom
  TLDs (.tk, .ml, .ga, .cf, .gq) held 60% of the phishing domains in all ccTLDs [3]. Its 2025 study
  ranks .xin, .bond, .help, .win and .cfd highest by "phishing score" [4], and Spamhaus reported a
  50% rise in abuse of .top in 2025 [5].

Blocklists (PhishTank, OpenPhish) always lag behind, because phishing sites are created
continuously and often disappear within hours. The goal of this project is a **machine-learning
classifier that decides from the URL string alone** whether a URL is benign or malicious. That
makes it fast and private enough to check every page a user opens in Chrome.

## 2. Objectives

1. Build a clean, de-duplicated and **unbiased** dataset of benign and malicious URLs.
2. Engineer lexical features computable from the URL alone (no page download, no WHOIS/DNS).
3. Compare 13 classifiers, including **ensemble learning** (bagging, boosting, voting, stacking),
   tune the best ones (with a focus on Random Forest), and select one model with a fixed, explicit
   rule.
4. Evaluate honestly: an untouched test set of **unseen websites**, live phishing (OpenPhish), and
   86 popular legitimate URLs.
5. Deploy as a REST API (FastAPI + Docker, Render) used by a Chrome extension.

## 3. Short literature review

* **Mamun et al. (2016) [7]** introduced the **ISCX-URL-2016** dataset (benign, spam, phishing,
  malware and defacement URLs) and showed that **lexical features of the URL string** (lengths,
  token statistics, counts of special characters, domain properties) are enough for ML classifiers
  to separate the categories. ISCX-URL-2016 is one of the sources of the Kaggle dataset we use [6].
  Our feature set follows the same lexical idea, and adds entropy, structure flags and a smoothed
  TLD reputation.
* **Prasad and Chandra (2024) [8]** built **PhiUSIIL**: 235,795 URLs, mostly from 2023, with a
  similarity index and incremental learning. Many of its 54 features come from the downloaded web
  page (HTML, title, forms). Because our API sees only the URL, we use **only its URL and label
  columns**. We also show that one of its features, `URLSimilarityIndex`, separates the classes
  almost perfectly on its own (ROC-AUC 0.996), so it is near-leaky.
* **Interisle (2023, 2025) [3, 4]**, **Spamhaus (2025) [5]** and **Krebs (2024) [10]** document how
  phishing concentrates on cheap or free TLDs and free hosting. This motivated our `suspicious_tld`
  flag and the learned `tld_malicious_rate`. Our OpenPhish test confirms it: 243 of 298 fresh
  phishing URLs sit on free hosting or site-builder platforms.

A gap we address: published results on these datasets usually use **random** splits. Section 7.6
measures how much that inflates the scores.

## 4. Datasets

| # | dataset | rows (raw) | classes | role |
|---|---|---:|---|---|
| 1 | Malicious URLs Dataset (Kaggle, sid321axn) [6]: ISCX-URL-2016, PhishTank, PhishStorm, malware lists | 651,097 | benign 428,101 · defacement 96,457 · phishing 94,019 · malware 32,520 | train / val / test |
| 2 | PhiUSIIL (UCI #967) [8] | 235,795 | legitimate 134,850 · phishing 100,945 | train / val / test |
| 3 | OpenPhish feed snapshot, 2026-11-24 [9] | 300 (298 unique) | live phishing | fresh test only |
| 4 | Real-world benign set (`data/external/realworld_benign_urls.csv`) | 86 | popular legitimate URLs (Google, banks, government, education, login pages) | false-positive test only; committed **before** training |

Labels: 0 = benign; 1 = malicious (phishing, malware or defacement).

## 5. Methodology

### 5.1 Data collection and preprocessing (Step 1)

**Loading.**
* The Kaggle CSV cannot be parsed by `read_csv`: 903 URLs contain unquoted commas. It is read line
  by line and split on the last comma.
* 94 rows are missing compared with the published count (651,191). This is documented, not
  recreated.
* PhiUSIIL's label is inverted (1 = legitimate) and is mapped explicitly.
* Downloads are verified by SHA-256. The PhiUSIIL mirror returned a Git LFS pointer, which the
  download script detects and handles.

**Cleaning: the data funnel.**
1. 886,892 raw rows.
2. **13,312** URLs repaired. These are scraping artefacts that a browser never sends and that are
   spread unevenly across classes (e.g. `&amp;` appears in 0 defacement URLs): HTML-escaped `&amp;`,
   `\%20`, octal byte escapes and wrapping quotes.
3. −40 non-printable rows, −10 URLs over 2,000 characters, −10 unparseable hosts.
4. **−8,977 rows from 4,194 URLs with conflicting labels.** All copies are dropped rather than
   guessing a label.
5. −20,037 duplicates within a source and −1,218 duplicates across sources.

Result: **856,600 URLs**: 554,078 benign (64.7%) and 302,522 malicious (35.3%), a ratio of 1.83 : 1.
There were no missing values in the raw columns, and 0 NaN/inf after feature extraction.

**The bias discovery and fix.**

| source · class | URL starts with a scheme | host starts with `www.` |
|---|---:|---:|
| Kaggle benign | 8.3% | 3.0% |
| Kaggle defacement | 100.0% | 69.6% |
| Kaggle malware | 94.9% | 3.5% |
| PhiUSIIL legitimate | 100.0% | 100.0% (and 0% have a path) |

* **What we found.** A one-flag classifier "has a scheme → malicious" reached **ROC-AUC 0.788** on
  Kaggle. "Has a path" reached 0.634 on PhiUSIIL. 4,132 Kaggle URLs were even labelled *phishing*
  with `http://` and *benign* without it.
* **The fix.** `normalize_url()` removes the scheme, `www.`, the fragment and the trailing `/`, and
  lowercases the host. No feature is created for the scheme or `www`.
* **The proof.** After normalisation every rate is 0% and every one-flag AUC is **0.500**. Merging
  the sources brings "has a path" down to AUC **0.510**.
* **Why it matters.** Chrome sends `https://www.google.com/search?q=x`; without this fix a model
  would have flagged Google.

**Features.**
* 48 lexical features plus 1 encoded feature:
  * lengths; counts of characters and parameters;
  * entropy and character ratios;
  * host structure: IP host, port, punycode, `@`, TLD-like label in the subdomain, embedded URL;
  * lexical signals: suspicious keywords, a brand outside the real domain, shortener,
    abused-TLD list, risky file extension, `.php` / `.htm`.
* `tld_malicious_rate` is an m-estimate (m = 50) target encoding, fitted on train only, with
  out-of-fold values for the training rows.
* 6 near-duplicate features were removed (|r| > 0.9, keeping the one with the higher mutual
  information), which leaves **43 features**.
* 856,600 URLs are processed in about 37 s.

**Split.** 70/15/15, **grouped by registered domain** (`StratifiedGroupKFold`, stratified by source
× type):
* train 591,470 / val 132,498 / test 132,632 rows;
* 321,423 domains, **0 shared** between splits.

A random split would put 65.8% of test URLs on domains seen in training. `StandardScaler` is fitted
on train only, for the linear and distance-based models.

### 5.2 Model training and tuning (Step 2)

**Rules.**
* The same 43 features, the same splits and `random_state=42` everywhere.
* Every cross-validation uses grouped folds.
* All models and timings are cached.

**Memory, not CPU, was the bottleneck.** A full-depth Random Forest on 591k rows needs about 2.2 GB
of RAM and ExtraTrees about 4.7 GB. Models were therefore trained one at a time, and a **memory
guard** limited the RF search to 5 parallel workers: the worst case was 1,061 MB per worker, against
7,044 MB of free RAM minus 1 GB.

**Ensemble learning used:**
* **Bagging:** Random Forest, Extra Trees, Bagging. Many deep trees on bootstrap samples are
  averaged.
* **Boosting:** AdaBoost, HistGradientBoosting, XGBoost, LightGBM. Trees are added in sequence,
  each fitting the remaining errors.
* **Soft Voting:** the averaged probabilities of RF, XGBoost and LightGBM.
* **Stacking:** a Logistic Regression meta-model on out-of-fold probabilities.

**Tuning:**
* **Random Forest.** `RandomizedSearchCV`, 25 candidates × 3 grouped folds on a 151,269-row
  domain-grouped subset, `refit="f1"`. Best: 200 trees, `max_depth=15`, `max_features=0.3`,
  `max_samples=0.8`, `class_weight="balanced"`, with CV F1 0.7319.
* **XGBoost.** 15 candidates. Best: 200 trees, depth 12, learning rate 0.05, subsample 0.8,
  colsample 0.7, reg_lambda 5.

**Deployability limits:** ≤ 25 MB compressed and ≤ 20 ms per URL, including feature extraction, on
1 thread.
* The tuned RF (34.7 MB) is too big. The smallest RF within 0.3 F1 points is **50 trees with
  min_samples_leaf 16: 6.5 MB, F1 0.7424**, against 0.7443 for the full tuned RF.

**Label-noise experiment.**
* We removed **7,897 documented noisy training rows**:
  * 3,760 Kaggle "phishing" pages on ietf.org / wikipedia.org;
  * 4,137 "benign" URLs containing `webscr`, PayPal phishing-kit paths.
* Result: noise-free validation F1 +1.41 points, so the rule fixed in advance adopted it.
* Nothing was relabelled.

**Threshold.** For each candidate, the threshold with the best validation F1 subject to **FPR ≤ 1%**.

**Selection rule:**
1. Deploy the tuned RF if it is within 1.0 F1 point of the best deployable candidate.
2. Otherwise deploy the best candidate, preferring an RF-containing ensemble within 1.0 point.

### 5.3 Evaluation

* **The test set is used once**, for the selected model plus the tuned RF as a reference.
* **Extra sets:** OpenPhish (recall) and the 86 real-world URLs (false positives).
* **Importance:** RF impurity importance and permutation importance (ΔROC-AUC, 20k validation rows,
  5 repeats).
* **Error analysis** on the 20 most confident test errors of each kind.

### 5.4 Deployment (Steps 3–4)

* **API:** FastAPI app `api/main.py`, reusing `src/predict.py` and `src/features.py` (no duplicated
  feature code). It provides:
  * Pydantic validation (empty input, > 2,048 characters, no parseable host → 422);
  * an LRU cache and a curated trusted-domain safety net;
  * open CORS (public, read-only, stateless);
  * no URL logging.
* **Hosting:** Docker (`python:3.14-slim`, pinned library versions, non-root user, `HEALTHCHECK`)
  on Render's free plan (Singapore) via `render.yaml`.
* **Chrome extension "URL Guard"** (Manifest V3): checks every main-frame navigation through the API,
  redirects malicious pages to a warning page, and blocks repeat visits instantly with
  `declarativeNetRequest`.

## 6. Results

### 6.1 Baseline comparison (validation, threshold 0.5)

| model | family | F1 | ROC-AUC | FPR | train–val F1 gap | size | latency |
|---|---|---:|---:|---:|---:|---:|---:|
| Stacking (RF+XGB+LGBM) | combination | **0.7425** | 0.8902 | 8.3% | 0.130 | 390.7 MB | 22.5 ms |
| Soft Voting (RF+XGB+LGBM) | combination | 0.7406 | **0.8908** | 7.4% | 0.159 | 390.7 MB | 18.6 ms |
| XGBoost | boosting | 0.7379 | 0.8859 | 8.1% | 0.112 | 1.6 MB | 4.7 ms |
| Random Forest | bagging | 0.7324 | 0.8736 | 9.0% | 0.233 | 387.9 MB | 13.0 ms |
| Extra Trees | bagging | 0.7307 | 0.8687 | 9.3% | 0.235 | 835.8 MB | 14.7 ms |
| LightGBM | boosting | 0.7307 | 0.8850 | 7.8% | 0.086 | 1.2 MB | 1.0 ms |
| HistGradientBoosting | boosting | 0.7206 | 0.8783 | 7.1% | 0.045 | 0.2 MB | 1.4 ms |
| Bagging (DT ×50) | bagging | 0.7103 | 0.8535 | 11.7% | 0.255 | 69.5 MB | 5.9 ms |
| KNN (100k sample) | single | 0.6657 | 0.8073 | 15.3% | 0.198 | 5.9 MB | 5.7 ms |
| Logistic Regression | single | 0.6424 | 0.8199 | 7.9% | 0.025 | 0.003 MB | 1.3 ms |
| Decision Tree | single | 0.6391 | 0.7197 | 21.6% | 0.326 | 1.8 MB | 1.1 ms |
| AdaBoost | boosting | 0.6065 | 0.8175 | 9.3% | 0.065 | 0.03 MB | 17.2 ms |
| Gaussian Naive Bayes | single | 0.4953 | 0.7994 | 2.7% | – | 0.002 MB | 1.3 ms |

Figures 14–17 show this table.
* The **ensembles** lead.
* The boosters reach almost the same F1 at a tiny fraction of the forests' size.
* Fully grown trees overfit strongly: a train–validation gap of 0.23–0.33.

### 6.2 Tuning

**Random Forest: default vs tuned**

| | F1 | ROC-AUC | gap | size |
|---|---:|---:|---:|---:|
| default | 0.7324 | 0.8736 | 0.233 | 387.9 MB |
| tuned | **0.7443** | 0.8790 | 0.088 | 34.7 MB |

**XGBoost: default vs tuned**

| | F1 | ROC-AUC | FPR |
|---|---:|---:|---:|
| default | 0.7379 | 0.8859 | 8.05% |
| tuned | **0.7409** | 0.8935 | 6.96% |

**Ensembles with the tuned, deployable members:** Soft Voting and Stacking reach **F1 0.7455**, at
13.0 / 12.7 MB instead of 391 MB. Figures 18 and 19 show the search and the size-vs-F1 trade-off.

### 6.3 Threshold and selection

Holding FPR ≤ 1% requires thresholds of 0.80–0.86 for the tree ensembles (0.56–0.90 across all
candidates). That raises precision to about 0.94–0.97 but lowers
recall to 0.25–0.49 (figure 20).

Applying the selection rule:
* **Best candidate:** XGBoost (tuned, noise removed), F1 **0.6542** at 0.80.
* **Deployable tuned RF:** F1 0.5502, which is 10.4 points behind, so it does not qualify.
* **Deployed: Soft Voting (tuned RF + tuned XGBoost + LightGBM, noise removed) at threshold 0.80.**
  It scores F1 0.6469, 0.73 points behind the best, contains RF, and has fewer real-world false
  positives (5 vs 9).

### 6.4 Final test (unseen websites, used once)

| model @ threshold | accuracy | precision | recall | F1 | ROC-AUC | PR-AUC | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Soft Voting (deployed) @ 0.80** | 0.8115 | **0.9657** | 0.4616 | **0.6246** | 0.8883 | 0.8478 | **0.84%** |
| RF tuned (reference) @ 0.85 | 0.7862 | 0.9654 | 0.3844 | 0.5499 | 0.8814 | 0.8362 | 0.71% |

* **Recall by type:** malware 84.6%, defacement 64.5%, phishing 31.9%.
* **By source:** F1 0.6106 on Kaggle and 0.6542 on PhiUSIIL.
* Figures 21–22 show the confusion matrix and the ROC/PR curves.

### 6.5 Fresh and real-world tests

* **OpenPhish** (298 unique live phishing URLs, 2026-11-24):
  * recall **79.2%** (236/298) overall;
  * free hosting / site builders: 92.6% (225/243);
  * **never-seen domains: 22.0% (11/50)**.
* **Real-world benign** (86 URLs, model only):
  * **5 false positives**: a Google Form, a Google Slides link, and the GitHub, PayPal and Netflix
    login pages;
  * banks, government, education and search URLs all stay below 0.70.
* **With the API's trusted list:** **1 false positive** (the Google Form, on purpose), and
  **OpenPhish recall unchanged at 79.19%**. The list decided 0 of the phishing URLs.

### 6.6 Split comparison: why our scores are lower than published ones (Step 5)

The same recipes were trained on a **random** stratified 70/15/15 split (notebook 03, figure 25).
In that split, **66.0%** of test URLs come from a domain also seen in training.

| recipe (evaluated on) | F1 random @0.5 | F1 grouped @0.5 | F1 random @FPR≤1% | F1 grouped @FPR≤1% | ROC-AUC random / grouped |
|---|---:|---:|---:|---:|---:|
| Soft Voting, deployed (test) | 0.8006 | 0.7303 | 0.7172 | 0.6246 | 0.9318 / 0.8883 |
| XGBoost tuned (val) | 0.8002 | 0.7437 | 0.7348 | 0.6542 | 0.9357 / 0.8930 |
| RF small_6 (val) | 0.7882 | 0.7374 | 0.6779 | 0.5502 | 0.9190 / 0.8741 |

* **Inflation:** the random split inflates F1 by **5–13 points**.
* **Source of the inflation:** inside the random test set, the deployed recipe scores F1 **0.805**
  on URLs from seen domains but **0.414** on URLs from unseen domains.

Our grouped evaluation measures the second situation, which is what a browser extension faces.

### 6.7 Feature importance and errors

* **Top feature:** both methods rank **`tld_malicious_rate`** first (permutation ΔROC-AUC 0.070,
  more than 3× the next feature).
* **Next:** path_len, num_dots, num_query_params, num_underscores, risky_file_extension, tld_len,
  num_digits and host_num_digits.
* **Agreement:** the rank correlation between impurity and permutation importance is 0.79
  (figure 24).
* **Errors:**
  * the 738 test false positives are mainly Joomla-style CMS pages and bare homepages on high-risk
    TLDs;
  * among the most confident false negatives are 82 Kaggle rows on springer.com, eweek.com,
    dailykos.com and linenghb.com, which are *further, undocumented label noise*.

### 6.8 Deployment numbers

| | value |
|---|---|
| model file | 13.3 MB (joblib, compress=3) |
| latency (1 URL incl. features, 1 thread) | 14.1 ms median, 19.8 ms p95 |
| memory | 195.6 → 246.6 MB RSS on loading the model (fresh process); API server 281 MB after start-up, 288 MB after 1,000 requests |
| local load test (1,000 requests, concurrency 20) | 0 errors, 101.5 requests/s, p50 199.8 ms, p95 273.3 ms, p99 326.8 ms |
| live API (Render free, Singapore) | `/predict` round trip median 103 ms (14.2 ms server-side); load test of 200 requests at concurrency 5: 0 errors, 8.1 requests/s, p50 610 ms, p95 907 ms |
| cold start (free instance after ≥ 16 min idle) | **34.1 s** to the first `/health` 200 after 19.0 min idle (container uptime 2.5 s at answer); then 98–144 ms warm (`reports/metrics/cold_start.json`) |

## 7. The Chrome extension (URL Guard)

* **Automatic protection.** When a tab starts loading a page, the URL goes to `POST /predict`. A
  malicious verdict redirects the tab to a warning page showing the probability and the reasons. A
  `declarativeNetRequest` rule then blocks repeat visits instantly.
* **Popup.** Paste any URL to check it by hand.
* **Settings.** Choose the Render, Local or Mock API, and test the connection.

**Design choices:**
* main frame only;
* verdict cache of 30 minutes;
* **fail-open** after 5 s, so that an API outage never makes browsing impossible;
* local addresses and browser pages are never sent;
* only the URL is sent (`credentials: "omit"`).

Its limitations are documented in `docs/04` §9. The main one: Manifest V3 has no blocking
`webRequest`, so a page can start loading before the verdict arrives. Repeat visits are blocked
instantly.

## 8. Testing summary

| layer | tests | result |
|---|---|---|
| features (`tests/test_features.py`) | normalisation, Google variants identical, IP/punycode/brand detection, 25 garbage inputs, batch == single, fast single-URL path == batch, TLD encoding, grouped folds | 54 passed |
| inference (`tests/test_predict.py`) | output schema, Google variants, IP phishing high + reason, garbage, batch == single, real-world CSV | 16 passed |
| API (`tests/test_api.py`) | health, contract, trusted list and user-content bypass, `model_only`, 422 cases incl. the 2,048/2,049-character boundary, batch limit, CORS, latency | 23 passed |
| extension (`node --test`) | API client, cache, rules, storage, URL rules, warning-link handling, navigation state | 66 passed |
| extension static check | 26 shipped files, 180 checks (manifest, permissions, files) | passed (1 documented warning: `<all_urls>`) |
| live API | all endpoints, 5/5 safe + 4/5 OpenPhish, 422, CORS, load test | passed |
| manual | Chrome extension verified manually by the team | passed |

## 9. Challenges and solutions (all steps)

| step | challenge | solution |
|---|---|---|
| 1 | Kaggle CSV unreadable (unquoted commas) | line-by-line parser splitting on the last comma |
| 1 | PhiUSIIL mirror served a Git LFS pointer; very slow connection | checksum check + LFS fallback; resumable downloads; `--verify-only` mode |
| 1 | label depends on URL formatting (scheme/www/path shortcuts) | `normalize_url()`, no scheme/www features, merged sources; proven with AUC 0.788 → 0.500 |
| 1 | same URL labelled phishing and benign (4,132 cases) | all conflicting copies dropped, no guessing |
| 1 | scraping artefacts spread unevenly across classes | repaired 13,312 URLs to their browser form |
| 1 | domain memorisation (65.8% of random-test URLs on known domains) | split grouped by registered domain |
| 1 | `GroupKFold(shuffle=True)` took 26 min on 225k groups | O(n) seeded grouped fold assignment (≈ 6 s), unit-tested |
| 2 | full-depth forests need 2–5 GB RAM; ~4.7 GB free | one big model at a time, cached; memory guard limited the search to 5 workers |
| 2 | single-URL feature extraction took ~10 ms | fast path, 0.32 ms, identical values |
| 2 | best forests 388–836 MB; Render needs small models | size/latency limits; 50-tree RF variant 6.5 MB within 0.3 F1 points |
| 2 | label noise (ietf.org "phishing", `webscr` "benign") | documented, removal experiment with a pre-set rule; adopted (+1.41 pts) |
| 2 | false alarms 7–14% at threshold 0.5 | threshold chosen for FPR ≤ 1% on validation |
| 2 | pandas 3 behaviour change; voting wrapper rejected by `permutation_importance` | `map(str)`; wrapper made a real scikit-learn classifier |
| 3 | popular login pages flagged by the model | curated trusted list that never trusts user-content hosts; 5 → 1 false positive, 0 phishing passed |
| 3 | Docker not running locally; slow link | Linux wheel availability checked by pip dry-run; image built by Render |
| 3 | big xgboost wheel | `xgboost-cpu` (same version and format) |
| 3 | extension URLs up to 2,048 characters | API limit raised from 2,000 to 2,048, boundary tested locally and live |
| 4 | no blocking `webRequest` in Manifest V3 | asynchronous check + `declarativeNetRequest` instant block for repeat visits; fail-open |
| 5 | "our scores are lower than papers" | controlled random-vs-grouped experiment (+5–13 F1 points from a random split) |

## 10. Limitations

1. **URL-only features cannot recognise phishing on brand-new, plain-looking domains.** Recall is
   22.0% on never-seen OpenPhish domains, and 0.414 F1 on unseen domains inside a random split.
2. **Holding false alarms at ≤ 1% costs recall:** 0.462 on test, and 31.9% for phishing.
3. **The labels contain noise** beyond what we documented: springer.com, eweek.com and similar
   pages labelled phishing.
4. **The training data is mostly from 2016–2023.** The OpenPhish snapshot is small (298 URLs).
5. **Free hosting has limits:** it sleeps after ~15 minutes, and its limited CPU gives about 8
   requests/s under concurrency.
6. **The extension** can let a page start loading before blocking it (Manifest V3) and fails open
   when the API is unreachable.

## 11. Future work

* Add **domain-age / WHOIS** and **TLS certificate** features in a second, slower tier, used only
  for uncertain URLs.
* Add **page-content features** (title, forms, brand logos) via an optional fetch, to catch
  plain-looking phishing domains.
* **Re-train periodically** on fresh feeds (OpenPhish, PhishTank), monitor drift, and re-check the
  threshold on recent data.
* Run an **active label-cleaning** pass on high-confidence disagreements.
* **Rate limiting** and API keys; a shared cache (Redis) for horizontal scaling; a paid instance
  without sleep.
* A **local model inside the extension** (e.g. ONNX) for offline checks.

## 12. Conclusion

We built a complete, reproducible pipeline: data collection, preprocessing, evaluation, a live API
and a Chrome extension. Its strongest contribution is **methodological honesty**:
* removing the formatting shortcuts;
* evaluating on unseen websites;
* fixing the real-world test set before training;
* using the test set once;
* reporting live phishing and false-positive tests.

The deployed ensemble is right **97% of the time when it raises an alarm**, keeps false alarms below
1% on new websites, and catches 79% of live phishing, much of it on free hosting. It still misses
most phishing on plain new domains, which is the fundamental limit of URL-only detection. We also
quantified that a random split would have made the same models look about 7 F1 points better.

## 13. Team contributions

| Name | PRN | Role | Contribution |
|---|---|---|---|
| Devendra Harale | 202401070086 | Data & EDA lead | Collected and verified the three datasets, built the cleaning and normalisation pipeline, and led the exploratory data analysis and the bias discovery |
| Shravani Vyaghrambare | 202401070124 | Modelling lead | Trained and compared the 13 models, tuned Random Forest and XGBoost, chose the decision threshold, and ran the final evaluation |
| Talha Shaikh | 202401070095 | Deployment lead | Built the FastAPI service and its tests, containerised it with Docker, and deployed it on Render |
| Shrutika Gaikwad | 202401070120 | Extension & documentation lead | Develops the Chrome extension and prepares the reports, documentation and presentation |

## 14. References

1. APWG, *Phishing Activity Trends Report*, Q1–Q4 2025. https://docs.apwg.org/reports/
2. FBI Internet Crime Complaint Center, *2024 Internet Crime Report*, 2025. https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf
3. Interisle Consulting Group, *Phishing Landscape 2023*. https://interisle.net/PhishingLandscape2023.html
4. Interisle Consulting Group, *Phishing Landscape 2025*. https://interisle.net/PhishingLandscape2025
5. Spamhaus, *Domain Reputation Update, April–September 2025*. https://www.spamhaus.org/resource-hub/domain-reputation/domain-reputation-update-april-september-2025/
6. M. Siddhartha (Kaggle user *sid321axn*), *Malicious URLs Dataset*, Kaggle, 2021. https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
7. M. S. I. Mamun, M. A. Rathore, A. H. Lashkari, N. Stakhanova, A. A. Ghorbani, "Detecting Malicious URLs Using Lexical Analysis", *Network and System Security (NSS)*, 2016. https://www.unb.ca/cic/datasets/url-2016.html
8. A. Prasad, S. Chandra, "PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning", *Computers & Security* 136, 103545, 2024. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
9. OpenPhish, public phishing feed. https://openphish.com/ (https://github.com/openphish/public_feed)
10. B. Krebs, "Why Phishers Love New TLDs Like .shop, .top and .xyz", KrebsOnSecurity, Dec 2024.

**Detailed reports:**
* `docs/01_data_preprocessing_report.md` (Step 1)
* `docs/02_model_training_evaluation_report.md` (Step 2 + split comparison)
* `docs/03_deployment_guide.md` (Step 3)
* `docs/04_extension_user_guide.md` (Step 4)
* `docs/06_demo_script.md` (demo)
