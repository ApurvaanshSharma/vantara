from app.models.alert import AlertSeverity


def _auth_headers(
    client, email="soar-routes@example.com", password="correcthorsebattery"
):
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = client.post(
        "/api/v1/auth/login", data={"username": email, "password": password}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_run_soar_requires_auth(client):
    response = client.post("/api/v1/soar/run")
    assert response.status_code == 401


def test_run_soar_processes_new_alerts(client, make_alert, monkeypatch):
    import app.soar.case_notify as case_notify_module

    monkeypatch.setattr(case_notify_module, "send_webhook", lambda payload: True)

    make_alert(severity=AlertSeverity.HIGH, details={"source_ip": "118.25.6.39"})
    make_alert(severity=AlertSeverity.LOW)

    headers = _auth_headers(client)
    response = client.post("/api/v1/soar/run", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["alerts_processed"] == 2
    assert body["total_playbook_runs"] == 6  # 3 playbooks x 2 alerts


def test_list_playbook_runs(client, make_alert, monkeypatch):
    import app.soar.case_notify as case_notify_module

    monkeypatch.setattr(case_notify_module, "send_webhook", lambda payload: True)
    make_alert(severity=AlertSeverity.CRITICAL, details={"source_ip": "118.25.6.39"})

    headers = _auth_headers(client)
    client.post("/api/v1/soar/run", headers=headers)

    response = client.get("/api/v1/soar/runs", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 3


def test_list_blocked_ips(client, make_alert, monkeypatch):
    import app.soar.case_notify as case_notify_module

    monkeypatch.setattr(case_notify_module, "send_webhook", lambda payload: True)
    make_alert(severity=AlertSeverity.HIGH, details={"source_ip": "203.0.113.5"})

    headers = _auth_headers(client)
    client.post("/api/v1/soar/run", headers=headers)

    response = client.get("/api/v1/soar/blocked-ips", headers=headers)
    assert response.status_code == 200
    ips = [b["ip_address"] for b in response.json()]
    assert "203.0.113.5" in ips
