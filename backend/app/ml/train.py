"""
Trains both models on synthetic data, evaluates both on the same held-out
split, saves artifacts.

Isolation Forest is trained WITHOUT labels (y is never passed to .fit()) —
that's the whole point of it being unsupervised. Labels are used only
afterward, to evaluate how well its unsupervised anomaly scoring lines up
with the synthetic ground truth. That's a legitimate, common way to sanity
-check an unsupervised model when labels happen to be available for
evaluation, even though the model itself never sees them during training —
worth being explicit that this is an evaluation-time convenience, not
something Isolation Forest depends on.
"""

import json

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from app.ml.model_store import (
    ISOLATION_FOREST_PATH,
    METRICS_PATH,
    RANDOM_FOREST_PATH,
    save_model,
)
from app.ml.synthetic_data import RANDOM_SEED, generate_dataset


def _evaluate(y_true, y_pred, model_name: str) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "model": model_name,
        "precision": round(float(precision), 3),
        "recall": round(float(recall), 3),
        "f1_score": round(float(f1), 3),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
    }


def train_and_evaluate() -> dict:
    X, y = generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y
    )

    # contamination = expected fraction of anomalies, estimated from the
    # training label distribution — a real number a production system
    # would tune against actual observed attack rates, not synthetic ones.
    contamination = float(np.mean(y_train))
    isolation_forest = IsolationForest(
        contamination=contamination, random_state=RANDOM_SEED, n_estimators=100
    )
    isolation_forest.fit(X_train)  # note: no y_train — unsupervised
    if_raw_pred = isolation_forest.predict(X_test)  # -1 = anomaly, 1 = normal
    if_pred = np.where(
        if_raw_pred == -1, 1, 0
    )  # translate to the same 0/1 scale as y_test

    random_forest = RandomForestClassifier(
        n_estimators=200, random_state=RANDOM_SEED, max_depth=8
    )
    random_forest.fit(X_train, y_train)
    rf_pred = random_forest.predict(X_test)

    metrics = {
        "isolation_forest": _evaluate(y_test, if_pred, "isolation_forest"),
        "random_forest": _evaluate(y_test, rf_pred, "random_forest"),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "contamination_estimate": round(contamination, 3),
    }

    save_model(isolation_forest, ISOLATION_FOREST_PATH)
    save_model(random_forest, RANDOM_FOREST_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))

    return metrics


if __name__ == "__main__":
    result = train_and_evaluate()
    print(json.dumps(result, indent=2))
