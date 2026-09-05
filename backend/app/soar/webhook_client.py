"""
Generic webhook delivery for the auto_case_notify playbook. Same
graceful-degradation contract as threat_intel/*_client.py: no configured
URL, or any delivery failure, returns False rather than raising — a
notification failing should never be the reason a case fails to get
created.
"""

import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)
_TIMEOUT_SECONDS = 5.0


def send_webhook(payload: dict) -> bool:
    if not settings.webhook_url:
        return False

    try:
        response = httpx.post(
            settings.webhook_url, json=payload, timeout=_TIMEOUT_SECONDS
        )
    except httpx.RequestError:
        logger.warning("Webhook delivery failed", exc_info=True)
        return False

    return response.status_code < 300
