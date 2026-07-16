"""
Inference: load both models once, score a feature vector, explain the
Random Forest prediction with SHAP.

shap_values indexing verified directly against this project's own trained
model and shap version before writing this — TreeExplainer here returns
shape (n_samples, n_features, n_classes), not the list-per-class format
older SHAP versions used. Indexing [0, :, 1] gets per-feature contributions
toward the "malicious" class (index 1) for the single sample being scored.
Getting this wrong wouldn't error — it would silently explain the wrong
class, which is worse than a crash.
"""

import numpy as np
import shap

from app.ml.features import FEATURE_NAMES
from app.ml.model_store import (
    ISOLATION_FOREST_PATH,
    RANDOM_FOREST_PATH,
    load_model,
    models_exist,
)

MALICIOUS_CLASS_INDEX = 1
TOP_N_SHAP_FEATURES = 3

_isolation_forest = None
_random_forest = None
_shap_explainer = None


def _ensure_models_loaded() -> None:
    global _isolation_forest, _random_forest, _shap_explainer
    if _isolation_forest is None:
        _isolation_forest = load_model(ISOLATION_FOREST_PATH)
    if _random_forest is None:
        _random_forest = load_model(RANDOM_FOREST_PATH)
    if _shap_explainer is None:
        _shap_explainer = shap.TreeExplainer(_random_forest)


def _feature_dict_to_vector(features: dict) -> np.ndarray:
    return np.array([[features[name] for name in FEATURE_NAMES]])


def top_shap_contributors(vector: np.ndarray) -> list[dict]:
    shap_values = _shap_explainer.shap_values(vector)
    per_feature = shap_values[0, :, MALICIOUS_CLASS_INDEX]
    ranked = sorted(
        zip(FEATURE_NAMES, per_feature), key=lambda pair: abs(pair[1]), reverse=True
    )
    return [
        {"feature": name, "shap_value": round(float(value), 4)}
        for name, value in ranked[:TOP_N_SHAP_FEATURES]
    ]


def score_features(features: dict) -> dict:
    """Returns a verdict dict regardless of whether models are trained yet
    — is_anomalous=False, model_ready=False when they aren't, rather than
    raising. Scoring should never be the reason a detection sweep fails."""
    if not models_exist():
        return {"model_ready": False, "is_anomalous": False}

    _ensure_models_loaded()
    vector = _feature_dict_to_vector(features)

    if_prediction = _isolation_forest.predict(vector)[0]  # -1 = anomaly, 1 = normal
    isolation_forest_anomaly = bool(if_prediction == -1)

    rf_probability = float(
        _random_forest.predict_proba(vector)[0][MALICIOUS_CLASS_INDEX]
    )

    # bool() here matters: `or` returns whichever operand it evaluates
    # truthy, not a coerced Python bool — without this, a numpy.bool_ from
    # isolation_forest_anomaly would leak through, which looks fine until
    # something downstream (JSON serialization, an `is True` check) treats
    # it as a different type than a real Python bool.
    is_anomalous = bool(isolation_forest_anomaly or rf_probability >= 0.5)

    result = {
        "model_ready": True,
        "is_anomalous": is_anomalous,
        "isolation_forest_anomaly": isolation_forest_anomaly,
        "random_forest_malicious_probability": round(rf_probability, 4),
    }

    if is_anomalous:
        result["top_shap_contributors"] = top_shap_contributors(vector)

    return result
