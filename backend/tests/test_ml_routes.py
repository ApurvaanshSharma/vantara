import app.api.routes.ml as ml_module


def _auth_headers(client, email="ml@example.com", password="correcthorsebattery"):
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = client.post(
        "/api/v1/auth/login", data={"username": email, "password": password}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_train_requires_auth(client):
    response = client.post("/api/v1/ml/train")
    assert response.status_code == 401


def test_train_returns_real_metrics(client):
    headers = _auth_headers(client)
    response = client.post("/api/v1/ml/train", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["isolation_forest"]["model"] == "isolation_forest"
    assert body["random_forest"]["model"] == "random_forest"
    assert 0.0 <= body["random_forest"]["f1_score"] <= 1.0


def test_metrics_requires_auth(client):
    response = client.get("/api/v1/ml/metrics")
    assert response.status_code == 401


def test_metrics_returns_data(client):
    headers = _auth_headers(client)
    response = client.get("/api/v1/ml/metrics", headers=headers)
    assert response.status_code == 200
    assert "random_forest" in response.json()


def test_score_requires_auth(client):
    response = client.post("/api/v1/ml/score")
    assert response.status_code == 401


def test_score_creates_alert_for_anomalous_ip(client, monkeypatch):
    monkeypatch.setattr(
        ml_module, "get_recent_active_ips", lambda lookback_minutes: ["118.25.6.39"]
    )
    monkeypatch.setattr(
        ml_module,
        "extract_features",
        lambda ip, lookback_minutes: {
            "total_events": 90.0,
            "failed_login_count": 70.0,
            "distinct_users": 12.0,
            "distinct_hosts": 5.0,
            "firewall_block_count": 2.0,
            "distinct_source_types": 2.0,
            "events_per_minute": 5.0,
            "night_time_ratio": 0.8,
        },
    )

    headers = _auth_headers(client)
    response = client.post("/api/v1/ml/score", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["ips_scanned"] == 1
    assert body["alerts_created"] == 1

    alerts = client.get("/api/v1/detections/alerts", headers=headers).json()
    ml_alerts = [a for a in alerts if a["detection_type"] == "ml"]
    assert len(ml_alerts) == 1
    assert ml_alerts[0]["mitre_techniques"] == []  # deliberately no MITRE tag
    assert "top_shap_contributors" in ml_alerts[0]["details"]


def test_score_creates_no_alert_for_benign_ip(client, monkeypatch):
    monkeypatch.setattr(
        ml_module, "get_recent_active_ips", lambda lookback_minutes: ["8.8.8.8"]
    )
    monkeypatch.setattr(
        ml_module,
        "extract_features",
        lambda ip, lookback_minutes: {
            "total_events": 2.0,
            "failed_login_count": 0.0,
            "distinct_users": 1.0,
            "distinct_hosts": 1.0,
            "firewall_block_count": 0.0,
            "distinct_source_types": 1.0,
            "events_per_minute": 0.05,
            "night_time_ratio": 0.1,
        },
    )

    headers = _auth_headers(client)
    response = client.post("/api/v1/ml/score", headers=headers)
    body = response.json()
    assert body["ips_scanned"] == 1
    assert body["alerts_created"] == 0
