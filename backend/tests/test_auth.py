from app.models.user import User, UserRole

TEST_EMAIL = "analyst@example.com"
TEST_PASSWORD = "correcthorsebattery"


def register(client, email=TEST_EMAIL, password=TEST_PASSWORD):
    return client.post(
        "/api/v1/auth/register", json={"email": email, "password": password}
    )


def login(client, email=TEST_EMAIL, password=TEST_PASSWORD):
    # OAuth2PasswordRequestForm expects form-encoded data, not JSON.
    return client.post(
        "/api/v1/auth/login", data={"username": email, "password": password}
    )


def test_register_creates_analyst_by_default(client):
    response = register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == TEST_EMAIL
    assert body["role"] == "analyst"
    assert "hashed_password" not in body  # schema must never leak this


def test_register_duplicate_email_rejected(client):
    register(client)
    response = register(client)
    assert response.status_code == 409


def test_login_success_returns_both_tokens(client):
    register(client)
    response = login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]


def test_login_wrong_password_rejected(client):
    register(client)
    response = login(client, password="wrong-password")
    assert response.status_code == 401


def test_me_rejects_missing_token(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_me_returns_current_user_with_valid_token(client):
    register(client)
    token = login(client).json()["access_token"]
    response = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == TEST_EMAIL


def test_refresh_issues_new_access_token(client):
    register(client)
    refresh_token = login(client).json()["refresh_token"]
    response = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    assert response.json()["access_token"]


def test_refresh_rejects_an_access_token_used_as_refresh(client):
    register(client)
    access_token = login(client).json()["access_token"]
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401


def test_admin_check_blocks_analyst(client):
    register(client)
    token = login(client).json()["access_token"]
    response = client.get(
        "/api/v1/auth/admin-check", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


def test_admin_check_allows_admin(client, db_session):
    register(client)
    # Simulates what scripts/create_admin.py does — flips the role directly,
    # proving the RBAC dependency reads role from the DB correctly.
    user = db_session.query(User).filter(User.email == TEST_EMAIL).first()
    user.role = UserRole.ADMIN
    db_session.commit()

    token = login(client).json()["access_token"]
    response = client.get(
        "/api/v1/auth/admin-check", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "Welcome, admin" in response.json()["message"]
