# Step 2 Report: Model Training, Comparison, Tuning and Evaluation

**Project:** Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)
**Notebook:** `notebooks/02_model_training_evaluation.ipynb` (executed). HTML copy: `reports/02_model_training_evaluation.html`
**Code:** `src/modeling.py` (cache, metrics, thresholds), `src/data.py` (grouped folds/samples),
`src/predict.py` (inference API), `scripts/step2_benchmark.py`, `scripts/measure_memory.py`

Every number below comes from the executed notebook. Tables are saved in `reports/metrics/`,
figures in `reports/figures/14–24_*.png`.

---

## 1. Goal

Train and compare classifiers that decide from the **URL string alone** whether a URL is benign
(0) or malicious (1: phishing, malware or defacement). Then select one model that is accurate,
produces few false alarms on everyday browsing, and is small and fast enough for a free Render
instance (**≤ 25 MB** compressed, **≤ 20 ms** per URL including feature extraction, 512 MB RAM).

## 2. Why classification, and why these algorithms

The labels are known and binary, and we have 856k labelled URLs, so this is **supervised binary
classification**. Models output P(malicious), and a threshold chosen on validation turns that
into a decision.

| family | models | reason to include |
|---|---|---|
| single | Logistic Regression, Decision Tree, KNN, Gaussian Naive Bayes | simple reference points (linear, one tree, distance-based, probabilistic) |
| bagging | Random Forest, Extra Trees, Bagging(DT) | averaging many deep trees reduces variance; RF is the project's focus |
| boosting | AdaBoost, HistGradientBoosting, XGBoost, LightGBM | sequential trees that correct each other's errors; usually the strongest on tabular data |
| combination | Soft Voting, Stacking (RF + XGB + LGBM) | combine different strong models |

**Ensemble learning in brief**
* **Bagging** trains many trees on bootstrap resamples (RF also uses random feature subsets) and
  averages them. The average of many different trees is far more stable than any single tree.
* **Boosting** adds small trees one after another, each fitting the errors of the ensemble so far.
* **Soft voting** averages the probabilities of several different models.
* **Stacking** trains a meta-model (Logistic Regression) on the out-of-fold predictions of the
  base models, so it learns how much to trust each one.

## 3. Setup

* **Data:** the Step 1 splits, grouped by registered domain:
  * train 591,470 / validation 132,498 / test 132,632 rows;
  * 43 features in the order of `feature_list.json`;
  * `random_state=42` everywhere.
* **Cross-validation:** always **grouped by registered domain**. It uses the O(n) seeded fold
  assignment from Step 1 (`src/data.py::grouped_cv_splits`), passed to scikit-learn as an
  explicit list of splits.
* **Samples:** the KNN training set, the train-F1 sample and the tuning subset are made of whole
  domain groups with the class ratio kept (`grouped_sample`).
* **Measurements:**
  * Latency is for **one URL including feature extraction, on 1 CPU thread** (median of 200
    calls), the closest match to a small server.
  * Size is `joblib.dump(model, compress=3)`.
  * Process memory is measured in a fresh subprocess (`scripts/measure_memory.py`).
* **Caching:** every fitted model, its predictions and its timings are cached in `models/cache/`
  (gitignored). Re-executing the notebook reuses the real run instead of retraining.
* **Extra test sets** (never used for training or tuning):
  * the **OpenPhish snapshot** (2026-11-24): all phishing, so we measure recall;
  * **86 real-world benign URLs** (`data/external/realworld_benign_urls.csv`): all benign, so we
    count false positives. They are written exactly as Chrome sends them and were committed in
    `558b426`, *before* any model was trained.
### Search spaces

**Random Forest:** `RandomizedSearchCV`
* n_iter = 25, 3 grouped folds on a ~150k-row domain-grouped subset;
* scoring = F1, ROC-AUC, precision, recall, with `refit="f1"`.

| parameter | values |
|---|---|
| n_estimators | 100, 150, 200, 300, 400 |
| max_depth | 10, 15, 20, 25, 30, 40, None |
| min_samples_split | 2, 5, 10, 20 |
| min_samples_leaf | 1, 2, 4, 8 |
| max_features | sqrt, log2, 0.3, 0.5 |
| class_weight | None, balanced, balanced_subsample |
| max_samples | None, 0.5, 0.8 |

**Booster:** n_iter = 15, same folds and subset.

| parameter | values |
|---|---|
| learning_rate | 0.03, 0.05, 0.1, 0.2 |
| n_estimators | 200, 400, 600, 800 |
| max_depth / num_leaves | 4–12 / 31–255 |
| subsample | 0.6, 0.8, 1.0 |
| colsample_bytree | 0.5, 0.7, 0.9, 1.0 |
| min_child_weight / min_child_samples | 1–10 / 10–100 |
| reg_lambda | 0.5, 1, 2, 5 |

**Parallelism:** `n_jobs=1` inside each model. The RF search used **8 workers, not all 24**,
because only ~4.7 GB of RAM was free and 24 deep forests in parallel would need over 10 GB. The
booster search used all cores, since boosters are small in memory.

## 4. Baseline comparison (validation, threshold 0.5)

Full table: `reports/metrics/baseline_comparison.csv`. Figures 14–17.

| model | family | F1 | precision | recall | ROC-AUC | FPR | train-val F1 gap | size MB | latency ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Stacking (RF+XGB+LGBM) | combination | 0.7425 | 0.8173 | 0.6804 | 0.8902 | 8.3% | 0.130 | 390.7 | 22.5 |
| Soft Voting (RF+XGB+LGBM) | combination | 0.7406 | 0.8301 | 0.6684 | 0.8908 | 7.4% | 0.159 | 390.7 | 18.6 |
| XGBoost | boosting | 0.7379 | 0.8195 | 0.6711 | 0.8859 | 8.1% | 0.112 | 1.6 | 4.7 |
| Random Forest | bagging | 0.7324 | 0.8035 | 0.6728 | 0.8736 | 9.0% | 0.233 | 387.9 | 13.0 |
| Extra Trees | bagging | 0.7307 | 0.7976 | 0.6742 | 0.8687 | 9.3% | 0.235 | 835.8 | 14.7 |
| LightGBM | boosting | 0.7307 | 0.8214 | 0.6580 | 0.8850 | 7.8% | 0.086 | 1.2 | 1.0 |
| HistGradientBoosting | boosting | 0.7206 | 0.8294 | 0.6371 | 0.8783 | 7.1% | 0.045 | 0.2 | 1.4 |
| Bagging (DT ×50) | bagging | 0.7103 | 0.7570 | 0.6689 | 0.8535 | 11.7% | 0.255 | 69.5 | 5.9 |
| KNN (k=5, 100k sample) | single | 0.6657 | 0.6946 | 0.6391 | 0.8073 | 15.3% | 0.198 | 5.9 | 5.7 |
| Logistic Regression | single | 0.6424 | 0.7896 | 0.5414 | 0.8199 | 7.9% | 0.025 | 0.003 | 1.3 |
| Decision Tree (depth 54, 61,436 leaves) | single | 0.6391 | 0.6234 | 0.6557 | 0.7197 | 21.6% | 0.326 | 1.8 | 1.1 |
| AdaBoost (stumps) | boosting | 0.6065 | 0.7489 | 0.5096 | 0.8175 | 9.3% | 0.065 | 0.03 | 17.2 |
| Gaussian Naive Bayes | single | 0.4953 | — | — | 0.7994 | 2.7% | — | 0.002 | 1.3 |

**Why these scores are lower than published ones.** Every validation URL comes from a website
that is not in training (grouped split), and Step 1 removed the scheme/www/path shortcuts. Many
papers report about 0.97 on this Kaggle data using random splits that leak websites between train
and test. Our numbers measure what the Chrome extension faces: new websites, URL text only.

**Class weight** (`reports/metrics/class_weight.csv`): `balanced` raises recall but costs
precision.
* RF: F1 0.7324 → 0.7368, but FPR 9.0% → 13.0%.
* Logistic Regression: F1 0.6424 → 0.6694, but FPR 7.9% → 17.5%.

ROC-AUC is unchanged, so class weight mostly shifts the threshold, and section 7 tunes the
threshold explicitly.

## 5. Ensemble discussion

* **Bagging** forests reach good F1, but full-depth trees memorise the training URLs: the
  train–validation gap is 0.23–0.26, and the models are 70–836 MB.
* **Boosting** reaches the same or better F1 with small, shallow trees (gap 0.05–0.11), at
  0.2–5 MB and 1–5 ms.
* **Combining** RF with the boosters (voting/stacking) gives the best F1 and ROC-AUC (0.7455 with
  tuned members). The members make partly different mistakes, so the averaged probability is
  slightly better than any single model.

## 6. Tuning

* **RF search.** 25 candidates × 3 grouped folds on 151,269 rows took 12.5 min.
  * A memory guard set **5 workers**: the worst case per worker is 1,061 MB, and the budget was
    7,044 MB free RAM minus 1 GB.
  * Best: `n_estimators=200, max_depth=15, min_samples_leaf=1, min_samples_split=2,
    max_features=0.3, max_samples=0.8, class_weight="balanced"`, CV F1 0.7319.
  * The top-10 candidates lie within 0.014 F1 of each other, while the fold standard deviation is
    0.02–0.03.
* **Default vs tuned RF** (validation):

| | F1 | precision | recall | ROC-AUC | FPR | F1 gap | size | latency |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| RF default | 0.7324 | 0.8035 | 0.6728 | 0.8736 | 9.0% | 0.233 | 387.9 MB | 13.0 ms |
| RF tuned | **0.7443** | 0.7588 | 0.7304 | 0.8790 | 12.6% | 0.088 | 34.7 MB | 13.0 ms |

* **Deployability.** The tuned RF (34.7 MB) is over 25 MB, so we tested 10 smaller variants
  (`reports/metrics/rf_size_vs_f1.csv`, figure 19).
  * The smallest within 0.3 F1 points is **50 trees, min_samples_leaf 16**: 6.5 MB, 3.4 ms,
    F1 0.7424 (−0.19 points).
* **XGBoost search.** 15 candidates in 1.0 min.
  * Best: 200 trees, depth 12, learning rate 0.05, subsample 0.8, colsample 0.7, reg_lambda 5.
  * Validation F1 0.7379 → 0.7409, FPR 8.05% → 6.96%, ROC-AUC 0.8859 → 0.8935, size 5.0 MB.
* **Tuned Voting / Stacking** (deployable RF + tuned XGBoost + LightGBM): F1 0.7455 each, at
  13.0 / 12.7 MB instead of 391 MB.
* **Label-noise experiment.** We removed 7,897 training rows: 3,760 ietf/wikipedia "phishing"
  rows and 4,137 `webscr` "benign" rows.
  * Noise-free validation F1 of the deployable RF at its threshold: 0.5361 → **0.5503 (+1.41
    points)**.
  * Real-world false positives stayed at 0; OpenPhish recall went 76.5% → 75.8%.
  * The rule fixed in advance says **train without the noisy rows**, so the final candidates
    were retrained that way. Nothing was relabelled.

## 7. Decision threshold

For each candidate: the threshold with the best validation F1 subject to **FPR ≤ 1%**
(`reports/metrics/candidates_threshold.csv`, figure 20). F1 at 0.5 is about 0.74, but FPR there is
7–14%. Keeping FPR ≤ 1% needs thresholds of 0.80–0.88: precision ≈ 0.96, recall ≈ 0.37–0.49.

## 8. Selection decision

* **Candidates:**
  * 19 models: ≤ 25 MB, ≤ 20 ms, able to reach FPR ≤ 1%, and not superseded by a noise-removed
    retrain.
  * Excluded for size/latency: the full-depth forests, the full tuned RF and the default-RF
    ensembles.
  * Excluded because they never reach 1% FPR: Decision Tree, KNN, Naive Bayes.
* **Best candidate:** XGBoost (tuned, noise removed), F1 **65.42** at threshold 0.80.
* **The tuned deployable RF** (noise removed) scores 55.02, 10.4 points behind, so it is **not**
  within 1.0 point.
* **RF-containing ensemble within 1.0 point:** **Soft Voting (tuned RF + tuned XGBoost + LightGBM,
  noise removed)** at 64.69, 0.73 points behind. It also has fewer real-world false positives
  (5 vs 9).
* **Deployed:** Soft Voting at **threshold 0.80**, 13.3 MB, 14.1 ms.

## 9. Final test metrics (test set used once)

| model @ threshold | accuracy | precision | recall | F1 | ROC-AUC | PR-AUC | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Soft Voting (selected) @ 0.80** | 0.8115 | **0.9657** | 0.4616 | **0.6246** | 0.8883 | 0.8478 | **0.84%** |
| RF tuned (reference) @ 0.85 | 0.7862 | 0.9654 | 0.3844 | 0.5499 | 0.8814 | 0.8362 | 0.71% |

* **Recall by type:** malware 84.6%, defacement 64.5%, phishing 31.9%. Benign FPR is 0.84%.
* **By source:** Kaggle F1 0.6106 (FPR 1.04%), PhiUSIIL F1 0.6542 (FPR 0.19%).
* **Generalisation:** test F1 (0.6246) is close to validation F1 (0.6469), so the threshold did
  not overfit validation.

## 10. Fresh and real-world tests

* **OpenPhish** (298 unique live phishing URLs, 2026-11-24): recall **79.2%** (236/298).
  * Free hosting / site builders: 92.6% (225/243, mostly `*.pages.dev`, a platform seen in
    training).
  * Never-seen domains: only **22.0%** (11/50).
  * The misses are plain-looking or look-alike domains (`sh0pify15.com`, `roblox.com.pt`,
    `inboxmailapp.com`) whose URL text resembles a normal small site.
* **Real-world benign** (86 URLs, committed before training): **5 false positives**.
  * They are Google Forms (0.834), Google Slides (0.825), and the GitHub (0.824), PayPal (0.823)
    and Netflix (0.818) login pages.
  * Banks, government, education, Wikipedia and search URLs all stay below 0.70.
  * The API adds a trusted-domain list for this; notebook metrics are model-only.

## 11. Feature importance

Both methods rank **tld_malicious_rate** first (impurity 0.229, permutation ΔROC-AUC 0.070,
more than 3× the next). Then come path_len, num_dots, num_query_params, num_underscores,
risky_file_extension, tld_len, num_digits and host_num_digits. The Spearman rank correlation
between the two methods is 0.79. Permutation ranks rare binary/count features higher
(risky_file_extension 6th vs 28th by impurity), because impurity importance is biased towards
high-cardinality features. Figure 24.

## 12. Error analysis (test)

* **738 false positives**, mainly:
  * Joomla-style CMS pages labelled benign (`index.php?option=com_content…`), overlapping with
    defacement;
  * bare PhiUSIIL homepages on high-risk TLDs (`.ga`, `.xyz`, `.top`).
* **24,263 false negatives**, mostly normal-looking URLs. Among the most confident misses,
  **82 Kaggle "phishing/malware" rows** on springer.com, eweek.com, dailykos.com and linenghb.com
  look like ordinary article and product pages: more label noise of the ietf.org kind.
* Only 11 errors (0.04%) match the Step 1 noise patterns, because those domains are concentrated
  in train.

## 13. Deployment readiness

| | value |
|---|---|
| file | `models/best_model.joblib`, **13.3 MB** (compress=3) |
| latency | **14.1 ms** median, 19.8 ms p95 (1 URL incl. features, 1 thread) |
| throughput | 6,306 URLs/s (batch, 1 thread) |
| memory | RSS 195.6 MB → **246.6 MB** after loading (fresh process); load 0.17 s |
| metadata | `models/model_metadata.json`: model, parameters, threshold 0.80, feature list + SHA-256, versions, metrics, label-noise decision |
| inference API | `src/predict.py`: `load_artifacts()`, `predict_url()`, `predict_batch()`, up to 3 reasons ordered by permutation importance |

## 14. Issues encountered and how they were solved

1. **Memory, not CPU, was the limit.**
   * A full-depth RF needs 2.2 GB of RAM and ExtraTrees 4.7 GB, with ~4.7 GB free.
   * Fix: models are trained one at a time and cached, and a memory guard limits the RF search to
     5 workers.
   * A first search with 8 workers was stopped before it could page.
2. **Single-URL feature extraction took ~10 ms** because it used the batch pandas path. A fast
   path brought it to 0.32 ms with identical values (unit-tested).
3. **pandas 3 `astype(str)` keeps `None` as missing.** This broke one plot; fixed with `map(str)`.
4. **`permutation_importance` rejected the prefit Soft Voting wrapper.** Made it a real
   scikit-learn classifier; predictions are unchanged (verified).
5. **The threshold fallback admitted models that can never reach FPR ≤ 1%,** and the candidate pool
   still contained superseded noisy-train models. Both are now excluded (this did not change the
   selection).
6. **The stacking model pickled its CV fold indices.** Dropped after fitting.

## 15. Limitations

* URL-only features cannot recognise phishing on brand-new, plain-looking domains (22% recall on
  never-seen OpenPhish domains).
* The FPR ≤ 1% operating point halves recall compared with 0.5. That is a deliberate trade-off for
  a browser extension.
* The Kaggle labels contain more noise than documented (section 12), which also lowers the
  measured scores.
* The test data is from 2016–2023. The OpenPhish snapshot is small (298 URLs).

## 16. How to reproduce

See `README.md` → "How to run Step 2". `scripts/step2_benchmark.py` runs first, then the notebook
(the first run trains about 33 models; later runs use `models/cache/`), then `pytest`.
