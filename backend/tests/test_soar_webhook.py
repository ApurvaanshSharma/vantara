import respx
from httpx import Response

from app.core.config import settings
from app.soar import webhook_client


@respx.mock
def test_no_webhook_url_returns_false_without_calling_out(monkeypatch):
    monkeypatch.setattr(settings, "webhook_url", "")
    assert webhook_client.send_webhook({"event": "test"}) is False


@respx.mock
def test_successful_delivery_returns_true(monkeypatch):
    monkeypatch.setattr(settings, "webhook_url", "https://hooks.example.com/notify")
    respx.post("https://hooks.example.com/notify").mock(return_value=Response(200))
    assert webhook_client.send_webhook({"event": "test"}) is True


@respx.mock
def test_server_error_returns_false(monkeypatch):
    monkeypatch.setattr(settings, "webhook_url", "https://hooks.example.com/notify")
    respx.post("https://hooks.example.com/notify").mock(return_value=Response(500))
    assert webhook_client.send_webhook({"event": "test"}) is False


@respx.mock
def test_network_error_returns_false_not_raises(monkeypatch):
    import httpx

    monkeypatch.setattr(settings, "webhook_url", "https://hooks.example.com/notify")
    respx.post("https://hooks.example.com/notify").mock(
        side_effect=httpx.ConnectError("refused")
    )
    assert webhook_client.send_webhook({"event": "test"}) is False
