# Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)

Computational Intelligence course project. A model classifies a URL as **benign** or
**malicious** (phishing, malware or defacement) **from the URL string alone**. It is served by a
FastAPI service on Render and called by the **URL Guard** Chrome extension for every page the user opens.

**Quick links**
- **Live API:** https://malicious-url-api.onrender.com
  - Swagger UI: https://malicious-url-api.onrender.com/docs
  - health: `/health`
- **Final report:** [docs/05_final_report.md](docs/05_final_report.md). All documents:
  [docs/README.md](docs/README.md).
- **Step reports:**
  - [01 data](docs/01_data_preprocessing_report.md)
  - [02 models (+ random vs grouped split, §17)](docs/02_model_training_evaluation_report.md)
  - [03 deployment](docs/03_deployment_guide.md)
  - [04 extension](docs/04_extension_user_guide.md)
- **Demo script for presentation day:** [docs/06_demo_script.md](docs/06_demo_script.md)
- **Executed notebooks:** `notebooks/01_…`, `02_…`, `03_split_comparison.ipynb` (HTML copies in
  `reports/`)
- **Load the extension:** see [below](#load-the-chrome-extension-url-guard).

| Step | Deliverable | Status |
|---|---|---|
| 1 | Data collection, preprocessing, EDA (`notebooks/01_…`, `docs/01_…`) | done |
| 2 | Training, comparison, tuning, evaluation (`notebooks/02_…`, `docs/02_…`) | done |
| 3 | FastAPI service, Docker, Render deployment (`api/`, `docs/03_deployment_guide.md`) | done |
| 4 | Chrome extension "URL Guard" (`extension/`, `docs/04_extension_user_guide.md`) | done |
| 5 | Split comparison, demo kit, final report (`notebooks/03_…`, `docs/05_…`, `docs/06_…`) | done |

**Run the API locally (one command, from the project root, venv installed):**
```powershell
.\.venv\Scripts\python.exe -m uvicorn api.main:app --port 8000
```
Then open http://127.0.0.1:8000/docs. See `docs/03_deployment_guide.md` for Docker, Render and the
API contract.

### Load the Chrome extension (URL Guard)
1. Open Chrome and go to `chrome://extensions`.
2. Switch on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension/` folder (the one that contains `manifest.json`).
4. Pin it: puzzle icon in the toolbar → pin next to **URL Guard**.

It uses the live API by default. Before a demo, open **Options → Test connection** (a sleeping free
Render server can take up to a minute to wake). After editing files in `extension/`, press the reload
arrow on its card in `chrome://extensions`. Extension tests (Node only, no `npm install`):
```powershell
node --test "extension/tests/*.test.mjs"
```
```powershell
node extension/dev/check_extension.mjs
```
Full guide, including permissions, privacy, limitations and a demo script:
`docs/04_extension_user_guide.md`.

## Folder structure

```
data/
  raw/            downloaded source datasets (not in git; recreate with scripts/download_data.py)
  external/       OpenPhish snapshot = unseen fresh test set (never used for training)
  processed/      urls_clean.csv(.zip), train/val/test.parquet (not in git; recreate with the notebook)
                  feature_list.json (in git: the ordered feature names the API must use)
api/              main.py: FastAPI service (Step 3)
docs/             00_project_proposal.md, 01_data_preprocessing_report.md, 02_model_training_evaluation_report.md,
                  03_deployment_guide.md, 04_extension_user_guide.md
extension/        URL Guard Chrome extension (Manifest V3, plain JavaScript) + tests/ and dev/ tools
models/           best_model.joblib + model_metadata.json (deployed model), feature_extractor.joblib,
                  scaler.joblib, type_label_encoder.joblib; cache/ (training cache, not in git)
notebooks/        01_data_preprocessing_eda.ipynb, 02_model_training_evaluation.ipynb (executed)
reports/          HTML copies of the notebooks, figures/ (PNG, dpi 150), metrics/ (CSV/JSON results)
scripts/          download_data.py, step2_benchmark.py, measure_memory.py, load_test.py, live_test.py, ...
src/              shared code: config.py, data.py, features.py, modeling.py, predict.py, trusted_domains.py, viz.py
tests/            test_features.py, test_predict.py, test_api.py (pytest)
Dockerfile, render.yaml, requirements-api.txt   deployment (Step 3)
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
