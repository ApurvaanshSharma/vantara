"""
AbuseIPDB v2 CHECK endpoint client.

Request/response shapes verified against AbuseIPDB's own documentation
(docs.abuseipdb.com) — not guessed. Every failure mode (missing key, rate
limit, network error, malformed response) returns None rather than raising:
a threat-intel lookup failing should degrade the enrichment for one IP, not
break the detection sweep that's calling it.
"""

import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT_SECONDS = 5.0


def check_ip(ip: str) -> dict | None:
    if not settings.abuseipdb_api_key:
        return None

    try:
        response = httpx.get(
            _BASE_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=_TIMEOUT_SECONDS,
        )
    except httpx.RequestError:
        logger.warning("AbuseIPDB request failed for %s", ip, exc_info=True)
        return None

    if response.status_code == 429:
        logger.warning("AbuseIPDB rate limit exceeded checking %s", ip)
        return None
    if response.status_code != 200:
        logger.warning("AbuseIPDB returned %s checking %s", response.status_code, ip)
        return None

    try:
        return response.json()["data"]
    except (KeyError, ValueError):
        logger.warning("AbuseIPDB response for %s missing expected 'data' key", ip)
        return None
