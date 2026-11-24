# Project Proposal: Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)

**Course:** Computational Intelligence (V Semester)

## Team

| Name | Role | Contribution |
|---|---|---|
| _name_ | _e.g. data & preprocessing lead_ | _e.g. dataset collection, cleaning, EDA_ |
| _name_ | _e.g. modelling lead_ | _e.g. model comparison, Random Forest tuning_ |
| _name_ | _e.g. deployment lead_ | _e.g. FastAPI service, Docker, Render_ |
| _name_ | _e.g. extension & report lead_ | _e.g. Chrome extension, documentation_ |

---

## 1. Problem statement

A malicious URL is a web address that leads to a phishing page (it steals passwords or card
details), to malware (it downloads harmful software), or to a hacked ("defaced") website. Users
open URLs from email, SMS, chat apps and search results many times a day, and most people cannot
tell a malicious URL from a real one by looking at it.

Blocklists such as PhishTank and OpenPhish only contain URLs that someone has already reported.
New phishing sites are created all the time, and many are taken down within hours, so a blocklist
is always a step behind. We therefore want a **machine-learning model that judges a URL it has
never seen before, using only the URL text**. Such a model is fast enough to check every page a
user opens.

### Why it matters

* The **Anti-Phishing Working Group (APWG)** observed 1,003,924 phishing attacks in Q1 2025,
  1,130,393 in Q2, 892,494 in Q3 and 853,244 in Q4. That is about **3.88 million attacks in one
  year** [1].
* The **FBI Internet Crime Complaint Center (IC3)** received 859,532 complaints in 2024 with
  reported losses of **US $16.6 billion**. **Phishing/spoofing was the most reported crime type,
  with 193,407 complaints** [2].
* Attackers pick cheap or free domain names. Interisle found that in November 2022 the free
  Freenom TLDs (.tk, .ml, .ga, .cf, .gq) hosted 60% of the phishing domains in all country-code
  TLDs [3]. Its 2025 study ranks .xin, .bond, .help, .win and .cfd highest by "phishing score" [4].
  Spamhaus reported a 50% rise in abuse of .top in April–September 2025 [5]. These patterns are
  visible in the URL itself, which is why lexical features can work.

## 2. Objectives

1. Build a clean, de-duplicated and **unbiased** dataset of benign and malicious URLs from public
   sources.
2. Engineer about 50 **lexical features** that can be computed from the URL string alone, with no
   page download and no WHOIS/DNS lookup, so the deployed service is fast and private.
3. Compare **13 classifiers**: 4 classic models, 3 bagging ensembles, 4 boosting ensembles, and 2
   meta-ensembles (soft voting and stacking). Then select the best model and tune it (focus:
   Random Forest).
4. Evaluate with accuracy, precision, recall, F1 and ROC-AUC on a held-out test set **of domains
   the model never saw**, plus a fresh snapshot of live phishing URLs (OpenPhish). Document the
   errors.
5. Deploy the model as a **REST API (FastAPI + Docker, hosted on Render)** and a **Chrome
   extension** that checks every URL the user opens.

## 3. Dataset plan

| # | Dataset | Content | Use |
|---|---|---|---|
| 1 | **Malicious URLs Dataset** (Kaggle, *sid321axn*) [6] | ~651k URLs in 4 classes: benign, defacement, phishing, malware. Compiled from ISCX-URL-2016 [7], PhishTank, PhishStorm and malware domain lists | training / validation / test |
| 2 | **PhiUSIIL Phishing URL Dataset** (UCI #967) [8] | 235,795 URLs (legitimate vs phishing), mostly collected in 2023 | training / validation / test (adds recent URLs) |
| 3 | **OpenPhish public feed** [9] | live phishing URLs at download time, saved as a dated snapshot | **fresh, unseen test set only, never used for training** |

**Label definition:** `label = 0` means benign. `label = 1` means malicious (phishing, malware or
defacement). The 4-class `type` is kept for an optional multi-class view.

**Known data risks we will handle in Step 1:**

* **Source bias.** URL formatting differs by source: Kaggle's benign URLs have no `http://` and
  no `www.`, and PhiUSIIL's legitimate URLs are all bare homepages. We normalize URLs and add no
  scheme/www features, so the model cannot learn the source instead of the threat.
* **Duplicates and label conflicts** across sources.
* **Domain leakage.** We split train/val/test **grouped by registered domain**, so test scores
  reflect new websites.

## 4. Approach

```
URLs ──► cleaning + normalisation ──► lexical features ──► model comparison ──► RF tuning ──► FastAPI (Docker, Render) ──► Chrome extension
```

### 4.1 Lexical features (Step 1)
These include lengths, character counts, entropy, subdomain structure, IP-address hosts,
punycode, `@` tricks, suspicious keywords (`login`, `verify`, …), brand names outside the real
domain (`paypal.com.evil.tk`), URL shorteners, abused TLDs, and a smoothed TLD reputation score
learned from training data. All are implemented once in `src/features.py`, which the API reuses
unchanged.

### 4.2 Model comparison, including ensemble learning (Step 2)

| Family | Models | Idea in one sentence |
|---|---|---|
| Single models | Logistic Regression, Decision Tree, KNN, Naive Bayes | one model learns the decision rule |
| **Bagging** | Random Forest, Extra Trees, Bagging | train many trees on random resamples of the data and random subsets of features, then **average their votes**. The trees make different mistakes, so the average is more stable |
| **Boosting** | AdaBoost, HistGradientBoosting, XGBoost, LightGBM | train trees **one after another**, each new tree **focusing on the errors** of the previous ones; the sum of many weak trees becomes a strong model |
| **Voting** | Soft Voting | average the predicted probabilities of several different models |
| **Stacking** | Stacking | a final "meta-model" **learns how much to trust** each base model's prediction |

We select the best model on the validation set (focus on F1 and recall for the malicious class,
since a missed phishing URL is worse than an extra warning). We then tune **Random Forest**
hyperparameters (number of trees, depth, `max_features`, `min_samples_leaf`, `class_weight`) with
grouped cross-validation, and compare `class_weight="balanced"` against no weighting.

### 4.3 Evaluation (Step 3)
We report accuracy, precision, recall, F1, ROC-AUC and the confusion matrix on the test set and
on the OpenPhish fresh set. We also analyze false positives on everyday sites (Google, banks,
university portals) and document the issues we find.

### 4.4 Deployment (Steps 4–5)
* **FastAPI** endpoint `POST /predict {"url": ...}` returns the malicious probability and a label.
  It loads `models/feature_extractor.joblib` plus the trained model, and is packaged with
  **Docker** and hosted on **Render**.
* **Chrome extension:** on every navigation it sends the URL to the API and shows a warning badge
  or page for malicious URLs.
* **Privacy:** the API only receives the URL, not page content. We will not store URLs.

## 5. Expected outcomes

* A reproducible pipeline (download script, notebooks, `src/` package, tests).
* A model that generalizes to **unseen domains** and to **fresh phishing URLs**. We will report
  how much performance drops from the grouped test set to the OpenPhish snapshot, rather than
  quoting a single optimistic accuracy.
* A working demo: Chrome extension + public API.
* Reports for each step: data insights, model comparison, evaluation, and deployment.

## 6. Tools

Python 3, pandas, NumPy, scikit-learn, XGBoost, LightGBM, tldextract, matplotlib, seaborn,
Jupyter, pytest, joblib, FastAPI, Docker, Render, Chrome Extensions (Manifest V3), Git.

## 7. Timeline

| Step | Deliverable | Status |
|---|---|---|
| 1 | Data collection, preprocessing, EDA (notebook + report) + this proposal | done |
| 2 | Model training and comparison (13 models) + RF tuning | next |
| 3 | Evaluation report (metrics, error analysis, fresh-URL test) | planned |
| 4 | FastAPI service in Docker on Render | planned |
| 5 | Chrome extension + final report and presentation | planned |

## References

1. APWG, *Phishing Activity Trends Report*, Q1, Q2, Q3 and Q4 2025.
   <https://docs.apwg.org/reports/apwg_trends_report_q1_2025.pdf>,
   <https://docs.apwg.org/reports/apwg_trends_report_q2_2025.pdf>,
   <https://docs.apwg.org/reports/apwg_trends_report_q3_2025.pdf>,
   <https://docs.apwg.org/reports/apwg_trends_report_q4_2025.pdf>
2. FBI Internet Crime Complaint Center, *2024 Internet Crime Report* (April 2025).
   <https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf>. Coverage:
   <https://www.securityweek.com/fbi-cybercrime-losses-surpassed-16-6-billion-in-2024/>
3. Interisle Consulting Group, *Phishing Landscape 2023*. <https://interisle.net/PhishingLandscape2023.html>
4. Interisle Consulting Group, *Phishing Landscape 2025* (Sept 2025). <https://interisle.net/PhishingLandscape2025>
5. Spamhaus, *Domain Reputation Update, April–September 2025*.
   <https://www.spamhaus.org/resource-hub/domain-reputation/domain-reputation-update-april-september-2025/>
6. M. Siddhartha (Kaggle user *sid321axn*), *Malicious URLs Dataset*, Kaggle, 2021. <https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset>
7. M. S. I. Mamun, M. A. Rathore, A. H. Lashkari, N. Stakhanova, A. A. Ghorbani, "Detecting
   Malicious URLs Using Lexical Analysis", *Network and System Security (NSS)*, 2016. Dataset:
   <https://www.unb.ca/cic/datasets/url-2016.html>
8. A. Prasad, S. Chandra, "PhiUSIIL: A diverse security profile empowered phishing URL detection
   framework based on similarity index and incremental learning", *Computers & Security* 136,
   103545, 2024. Dataset: <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset>
9. OpenPhish, public phishing feed. <https://openphish.com/> (feed mirror:
   <https://github.com/openphish/public_feed>)
10. B. Krebs, "Why Phishers Love New TLDs Like .shop, .top and .xyz", KrebsOnSecurity, Dec 2024.
    <https://krebsonsecurity.com/2024/12/why-phishers-love-new-tlds-like-shop-top-and-xyz/>
