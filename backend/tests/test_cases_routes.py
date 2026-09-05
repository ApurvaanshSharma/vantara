def _auth_headers(client, email="cases@example.com", password="correcthorsebattery"):
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = client.post(
        "/api/v1/auth/login", data={"username": email, "password": password}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_create_case_requires_auth(client):
    response = client.post("/api/v1/cases", json={"title": "Test", "severity": "high"})
    assert response.status_code == 401


def test_create_and_get_case(client):
    headers = _auth_headers(client)
    response = client.post(
        "/api/v1/cases",
        json={
            "title": "Suspicious login burst",
            "severity": "high",
            "tags": ["manual"],
        },
        headers=headers,
    )
    assert response.status_code == 201
    case = response.json()
    assert case["status"] == "open"
    assert case["title"] == "Suspicious login burst"

    get_response = client.get(f"/api/v1/cases/{case['id']}", headers=headers)
    assert get_response.status_code == 200
    assert get_response.json()["id"] == case["id"]


def test_get_nonexistent_case_404s(client):
    headers = _auth_headers(client)
    response = client.get(
        "/api/v1/cases/00000000-0000-0000-0000-000000000000", headers=headers
    )
    assert response.status_code == 404


def test_list_cases_filters_by_status(client):
    headers = _auth_headers(client)
    client.post(
        "/api/v1/cases", json={"title": "Open case", "severity": "low"}, headers=headers
    )
    closed = client.post(
        "/api/v1/cases",
        json={"title": "To be closed", "severity": "low"},
        headers=headers,
    ).json()
    client.post(f"/api/v1/cases/{closed['id']}/close", headers=headers)

    open_only = client.get("/api/v1/cases?status_filter=open", headers=headers).json()
    assert all(c["status"] == "open" for c in open_only)
    assert not any(c["id"] == closed["id"] for c in open_only)


def test_update_case_status_and_tags(client):
    headers = _auth_headers(client)
    case = client.post(
        "/api/v1/cases", json={"title": "Test", "severity": "medium"}, headers=headers
    ).json()

    response = client.patch(
        f"/api/v1/cases/{case['id']}",
        json={"status": "investigating", "tags": ["escalated"]},
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "investigating"
    assert body["tags"] == ["escalated"]


def test_close_case_sets_closed_at(client):
    headers = _auth_headers(client)
    case = client.post(
        "/api/v1/cases", json={"title": "Test", "severity": "low"}, headers=headers
    ).json()

    response = client.post(f"/api/v1/cases/{case['id']}/close", headers=headers)
    body = response.json()
    assert body["status"] == "closed"
    assert body["closed_at"] is not None


def test_add_and_list_comments(client):
    headers = _auth_headers(client)
    case = client.post(
        "/api/v1/cases", json={"title": "Test", "severity": "low"}, headers=headers
    ).json()

    comment_response = client.post(
        f"/api/v1/cases/{case['id']}/comments",
        json={"body": "Investigating source IP now."},
        headers=headers,
    )
    assert comment_response.status_code == 201

    list_response = client.get(f"/api/v1/cases/{case['id']}/comments", headers=headers)
    comments = list_response.json()
    assert len(comments) == 1
    assert comments[0]["body"] == "Investigating source IP now."


def test_comment_on_nonexistent_case_404s(client):
    headers = _auth_headers(client)
    response = client.post(
        "/api/v1/cases/00000000-0000-0000-0000-000000000000/comments",
        json={"body": "test"},
        headers=headers,
    )
    assert response.status_code == 404
