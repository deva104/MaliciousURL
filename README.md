# Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)

Computational Intelligence course project. A model classifies a URL as **benign** or
**malicious** (phishing, malware or defacement) **from the URL string alone**. It will be served by a
FastAPI service and called by a Chrome extension for every page the user opens.

**Live API:** https://malicious-url-api.onrender.com (interactive docs at `/docs`)

| Step | Deliverable | Status |
|---|---|---|
| 1 | Data collection, preprocessing, EDA (`notebooks/01_…`, `docs/01_…`) | done |
| 2 | Training, comparison, tuning, evaluation (`notebooks/02_…`, `docs/02_…`) | done |
| 3 | FastAPI service, Docker, Render deployment (`api/`, `docs/03_deployment_guide.md`) | done |
| 4 | Chrome extension | next |
| 5 | Final report + presentation | planned |

**Run the API locally (one command, from the project root, venv installed):**
```powershell
.\.venv\Scripts\python.exe -m uvicorn api.main:app --port 8000
```
Then open http://127.0.0.1:8000/docs. See `docs/03_deployment_guide.md` for Docker, Render and the
API contract.

## Folder structure

```
data/
  raw/            downloaded source datasets (not in git; recreate with scripts/download_data.py)
  external/       OpenPhish snapshot = unseen fresh test set (never used for training)
  processed/      urls_clean.csv(.zip), train/val/test.parquet (not in git; recreate with the notebook)
                  feature_list.json (in git: the ordered feature names the API must use)
docs/             00_project_proposal.md, 01_data_preprocessing_report.md
models/           feature_extractor.joblib, scaler.joblib, type_label_encoder.joblib
notebooks/        01_data_preprocessing_eda.ipynb (executed, with all outputs)
reports/          01_data_preprocessing_eda.html + figures/ (PNG, dpi 150)
scripts/          download_data.py (download + SHA-256 verification)
src/              shared code: config.py, data.py (load/clean/split), features.py (normalise + features), viz.py
tests/            test_features.py (pytest)
```

`src/features.py` holds the feature code for **both** training and the API, so the two can never
disagree.

## Environment setup (Windows, PowerShell)

Requires Python 3.10+ (developed on 3.14).

```powershell
py -3.14 -m venv .venv
```
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```
```powershell
.\.venv\Scripts\python.exe -m ipykernel install --user --name url-detection --display-name "Python (url-detection)"
```

On macOS/Linux, use `python3 -m venv .venv` and `.venv/bin/python` instead.

## How to run Step 1

1. **Download and verify the data.** This checks size + SHA-256 and skips files that are already
   correct.
   ```powershell
   .\.venv\Scripts\python.exe scripts\download_data.py
   ```
2. **Run the unit tests.**
   ```powershell
   .\.venv\Scripts\python.exe -m pytest
   ```
3. **Execute the notebook** top to bottom (writes all outputs in `data/processed/`, `models/`,
   `reports/figures/`), then export the HTML copy.
   ```powershell
   .\.venv\Scripts\python.exe -m jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=1800 notebooks\01_data_preprocessing_eda.ipynb
   ```
   ```powershell
   .\.venv\Scripts\python.exe -m jupyter nbconvert --to html --output-dir reports notebooks\01_data_preprocessing_eda.ipynb
   ```

## How to run Step 2 (model training and evaluation)

1. (Optional) Re-run the pre-flight benchmark and time plan:
   ```powershell
   .\.venv\Scripts\python.exe scripts\step2_benchmark.py
   ```
2. Execute the training notebook. The first run trains all models (~30 min on 24 cores). Every
   fitted model, prediction and timing is cached in `models/cache/` (gitignored), so later runs
   reuse the cache and finish in minutes.
   ```powershell
   .\.venv\Scripts\python.exe -m jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=7200 notebooks\02_model_training_evaluation.ipynb
   ```
   ```powershell
   .\.venv\Scripts\python.exe -m jupyter nbconvert --to html --output-dir reports notebooks\02_model_training_evaluation.ipynb
   ```
3. Run all tests (features + prediction API):
   ```powershell
   .\.venv\Scripts\python.exe -m pytest
   ```

Outputs:
- `models/best_model.joblib` and `models/model_metadata.json`: the selected model, its
  threshold, the feature list with its SHA-256, and all metrics
- `reports/metrics/*.csv`: comparison tables and timings
- `reports/figures/14_*.png` onwards
- `docs/02_model_training_evaluation_report.md`

Extra test sets in `data/external/` (never used for training):
- the OpenPhish snapshot
- `realworld_benign_urls.csv`: 86 legitimate URLs, committed before training

## Predicting a URL (what the API will call)

```python
from src.predict import predict_url, predict_batch
predict_url("https://www.google.com/search?q=x")
# {'url': ..., 'normalized_url': 'google.com/search?q=x', 'probability': ..., 'is_malicious': False,
#  'threshold': ..., 'reasons': [...]}
```

## Using the feature extractor (e.g. in the API)

```python
import joblib
fx = joblib.load("models/feature_extractor.joblib")   # needs the src/ package importable
X = fx.transform_one("https://www.example.com/login")  # 1-row DataFrame, columns in feature_list.json order
```

## Data sources

* Malicious URLs Dataset (Kaggle, sid321axn): ISCX-URL-2016, PhishTank, PhishStorm, malware domain lists
* PhiUSIIL Phishing URL Dataset (UCI #967, Prasad & Chandra 2024)
* OpenPhish public feed (dated snapshot, test only)

See `docs/00_project_proposal.md` for full citations.
