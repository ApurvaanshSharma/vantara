"""
Turns an anomalous score_features() result into an alert dict, matching
the same shape every other detection mechanism in this project produces.

No MITRE tag, deliberately — same principle as the firewall Sigma rule in
Phase 4: this is a behavior-based anomaly, not a signature match for a
specific technique. Attaching a tag just to have one would be
checkbox-mapping, not real mapping.

Dedup key uses the same hour-bucket pattern as correlation.py, for the
same reason: an IP that's still anomalous in the same hour on a later
sweep shouldn't produce a second alert.
"""

from datetime import datetime, timezone


def _severity_from_probability(rf_probability: float) -> str:
    if rf_probability >= 0.8:
        return "high"
    if rf_probability >= 0.5:
        return "medium"
    return "low"  # isolation_forest flagged it, but random_forest wasn't as confident


def build_ml_alert_dict(source_ip: str, features: dict, score_result: dict) -> dict:
    hour_bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    rf_probability = score_result["random_forest_malicious_probability"]
    contributors = score_result.get("top_shap_contributors", [])
    contributor_summary = ", ".join(f"{c['feature']}" for c in contributors)

    return {
        "rule_id": "ml.anomaly_detection",
        "rule_title": "ML-Based Anomalous Behavior",
        "detection_type": "ml",
        "severity": _severity_from_probability(rf_probability),
        "mitre_techniques": [],
        "source_event_id": f"ml_anomaly:{source_ip}:{hour_bucket}",
        "summary": (
            f"Anomalous behavior from {source_ip} "
            f"(malicious probability {rf_probability:.0%}, driven by: {contributor_summary})"
        ),
        "details": {
            "source_ip": source_ip,
            "features": features,
            "isolation_forest_anomaly": score_result["isolation_forest_anomaly"],
            "random_forest_malicious_probability": rf_probability,
            "top_shap_contributors": contributors,
        },
    }
