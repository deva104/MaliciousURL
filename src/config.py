"""Project-wide paths and constants."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RAW = DATA / "raw"
PROCESSED = DATA / "processed"
EXTERNAL = DATA / "external"
MODELS = ROOT / "models"
FIGURES = ROOT / "reports" / "figures"

KAGGLE_FILE = RAW / "malicious_phish.csv"
PHIUSIIL_FILE = RAW / "PhiUSIIL_Phishing_URL_Dataset.csv"
KAGGLE_PUBLISHED_ROWS = 651_191   # row count stated on the Kaggle dataset page

RANDOM_STATE = 42
MAX_URL_LEN = 2_000               # longer URLs are dropped (browsers/servers cap ~2k)
TLD_SMOOTHING_M = 50.0            # m-estimate smoothing for the TLD target encoding

TYPES = ("benign", "defacement", "phishing", "malware")
TYPE_TO_LABEL = {"benign": 0, "defacement": 1, "phishing": 1, "malware": 1}
