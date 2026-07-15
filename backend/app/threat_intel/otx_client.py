"""
AlienVault OTX 'general' indicator endpoint client, for IPv4 addresses.

Request/response shape verified against OTX's own external API docs and
official SDK examples — not guessed. Same graceful-degradation contract as
abuseipdb_client.py: any failure returns None, never raises.
"""

import logging

import httpx

from app.core.config import settings

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"
_TIMEOUT_SECONDS = 5.0

logger = logging.getLogger(__name__)


def check_ip(ip: str) -> dict | None:
    if not settings.otx_api_key:
        return None

    try:
        response = httpx.get(
            f"{_BASE_URL}/{ip}/general",
            headers={"X-OTX-API-KEY": settings.otx_api_key},
            timeout=_TIMEOUT_SECONDS,
        )
    except httpx.RequestError:
        logger.warning("OTX request failed for %s", ip, exc_info=True)
        return None

    if response.status_code == 429:
        logger.warning("OTX rate limit exceeded checking %s", ip)
        return None
    if response.status_code != 200:
        logger.warning("OTX returned %s checking %s", response.status_code, ip)
        return None

    try:
        return response.json()
    except ValueError:
        logger.warning("OTX response for %s was not valid JSON", ip)
        return None
