"""
Model artifact storage.

Binary model files are .gitignored (see root .gitignore) — training is
fast and deterministic (fixed RANDOM_SEED in synthetic_data.py), so the
training script is the source of truth, not a committed binary blob.
Standard MLOps practice: models are build artifacts, not source code.
"""

from pathlib import Path

import joblib

MODEL_DIR = Path(__file__).resolve().parents[2] / "ml_models"
ISOLATION_FOREST_PATH = MODEL_DIR / "isolation_forest.joblib"
RANDOM_FOREST_PATH = MODEL_DIR / "random_forest.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"


def save_model(model, path: Path) -> None:
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(model, path)


def load_model(path: Path):
    return joblib.load(path)


def models_exist() -> bool:
    return ISOLATION_FOREST_PATH.exists() and RANDOM_FOREST_PATH.exists()
