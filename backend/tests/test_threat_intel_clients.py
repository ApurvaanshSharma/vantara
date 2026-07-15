"""
These tests mock the HTTP layer (respx intercepts httpx before any real
socket connects) — no live API access happens here or anywhere else in
this suite. The mocked response bodies are copied from AbuseIPDB's and
OTX's own published documentation examples, not invented, so parsing logic
is validated against a real shape even though no real request is sent.
"""

import respx
from httpx import Response

from app.core.config import settings
from app.threat_intel import abuseipdb_client, otx_client


@respx.mock
def test_abuseipdb_check_ip_parses_real_shaped_response(monkeypatch):
    monkeypatch.setattr(settings, "abuseipdb_api_key", "test-key")
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "ipAddress": "118.25.6.39",
                    "isPublic": True,
                    "abuseConfidenceScore": 100,
                    "countryCode": "CN",
                    "totalReports": 1,
                    "lastReportedAt": "2018-12-20T20:55:14+00:00",
                }
            },
        )
    )
    result = abuseipdb_client.check_ip("118.25.6.39")
    assert result["abuseConfidenceScore"] == 100
    assert result["totalReports"] == 1


@respx.mock
def test_abuseipdb_returns_none_without_api_key(monkeypatch):
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    result = abuseipdb_client.check_ip("118.25.6.39")
    assert result is None


@respx.mock
def test_abuseipdb_returns_none_on_rate_limit(monkeypatch):
    monkeypatch.setattr(settings, "abuseipdb_api_key", "test-key")
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=Response(
            429,
            json={
                "errors": [
                    {
                        "detail": "Daily rate limit of 1000 requests exceeded",
                        "status": 429,
                    }
                ]
            },
        )
    )
    assert abuseipdb_client.check_ip("118.25.6.39") is None


@respx.mock
def test_otx_check_ip_parses_real_shaped_response(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", "test-key")
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/185.220.101.1/general"
    ).mock(
        return_value=Response(
            200,
            json={
                "indicator": "185.220.101.1",
                "type": "IPv4",
                "pulse_info": {
                    "count": 3,
                    "pulses": [
                        {
                            "id": "abc123",
                            "name": "Tor exit node scanning",
                            "malware_families": ["Generic"],
                            "tags": ["tor"],
                        }
                    ],
                },
            },
        )
    )
    result = otx_client.check_ip("185.220.101.1")
    assert result["pulse_info"]["count"] == 3


@respx.mock
def test_otx_returns_none_without_api_key(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", "")
    assert otx_client.check_ip("185.220.101.1") is None
