from app.ml.features import FEATURE_NAMES
from app.ml.inference import score_features


def _vector(**overrides) -> dict:
    base = dict.fromkeys(FEATURE_NAMES, 0.0)
    base.update(overrides)
    return base


def test_obviously_benign_vector_not_anomalous():
    features = _vector(
        total_events=3,
        failed_login_count=0,
        distinct_users=1,
        distinct_hosts=1,
        firewall_block_count=0,
        distinct_source_types=1,
        events_per_minute=0.1,
        night_time_ratio=0.2,
    )
    result = score_features(features)
    assert result["model_ready"] is True
    assert result["is_anomalous"] is False
    assert "top_shap_contributors" not in result  # only attached when anomalous


def test_obviously_malicious_vector_flagged_with_explanation():
    features = _vector(
        total_events=90,
        failed_login_count=70,
        distinct_users=12,
        distinct_hosts=5,
        firewall_block_count=2,
        distinct_source_types=2,
        events_per_minute=5.0,
        night_time_ratio=0.8,
    )
    result = score_features(features)
    assert result["model_ready"] is True
    assert result["is_anomalous"] is True
    assert 0.0 <= result["random_forest_malicious_probability"] <= 1.0
    assert len(result["top_shap_contributors"]) == 3
    for contributor in result["top_shap_contributors"]:
        assert contributor["feature"] in FEATURE_NAMES


def test_shap_contributors_ranked_by_absolute_value():
    features = _vector(
        total_events=90, failed_login_count=70, distinct_users=12, events_per_minute=5.0
    )
    result = score_features(features)
    values = [abs(c["shap_value"]) for c in result["top_shap_contributors"]]
    assert values == sorted(values, reverse=True)
