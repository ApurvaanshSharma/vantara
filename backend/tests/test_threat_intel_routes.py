import app.api.routes.threat_intel as threat_intel_module


def _auth_headers(client, email="intel@example.com", password="correcthorsebattery"):
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = client.post(
        "/api/v1/auth/login", data={"username": email, "password": password}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_lookup_requires_auth(client):
    response = client.get("/api/v1/threat-intel/118.25.6.39")
    assert response.status_code == 401


def test_lookup_private_ip_not_enrichable(client):
    headers = _auth_headers(client)
    response = client.get("/api/v1/threat-intel/10.0.0.5", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["enrichable"] is False
    assert body["combined_threat_score"] is None


def test_lookup_public_ip_returns_enrichment(client, monkeypatch):
    from app.models.ioc_enrichment import IOCEnrichment

    fake_enrichment = IOCEnrichment(
        indicator_type="ip",
        indicator_value="118.25.6.39",
        abuseipdb_score=75,
        abuseipdb_total_reports=12,
        otx_pulse_count=2,
        otx_malware_families=["Mirai"],
        combined_threat_score=57,
    )
    monkeypatch.setattr(
        threat_intel_module, "enrich_ip", lambda db, ip: fake_enrichment
    )

    headers = _auth_headers(client)
    response = client.get("/api/v1/threat-intel/118.25.6.39", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["enrichable"] is True
    assert body["combined_threat_score"] == 57
    assert body["otx_malware_families"] == ["Mirai"]
