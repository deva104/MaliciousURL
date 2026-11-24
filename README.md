# Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)

Computational Intelligence course project. A model classifies a URL as **benign** or
**malicious** (phishing, malware or defacement) **from the URL string alone**. It will be served by a
FastAPI service and called by a Chrome extension for every page the user opens.

**Status:** Step 1 (data collection, preprocessing, EDA) is complete. Steps 2–5 (models,
evaluation, API, extension) are still to come.

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
