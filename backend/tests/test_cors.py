"""
Regression test for a real bug found in live Phase 7 verification: the
backend had zero CORS configuration, so every browser-based request from
the frontend was silently blocked before reaching FastAPI at all. Nothing
before this caught it — curl and pytest's TestClient don't enforce or even
surface CORS the way a real browser does, which is exactly why it slipped
through five phases of backend-only testing undetected.
"""

from app.core.config import settings


def test_cors_configured_for_frontend_origin():
    assert "http://localhost:3000" in settings.cors_origins_list


def test_preflight_request_gets_cors_headers(client):
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert (
        response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    )


def test_actual_request_gets_cors_header(client):
    response = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert (
        response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    )


def test_disallowed_origin_does_not_get_cors_header(client):
    response = client.get("/health", headers={"Origin": "http://evil.example.com"})
    assert response.headers.get("access-control-allow-origin") is None
