"""
Redis connection and Stream constants.

One Redis Stream ("vantara:events:raw") holds every ingested event before
normalization. One consumer group ("normalizers") lets multiple Celery
workers pull from the same stream without processing the same entry twice —
Redis tracks which consumer is handling which entry and won't hand it to
another until it's acknowledged or explicitly claimed back.
"""

import redis

from app.core.config import settings

STREAM_KEY = "vantara:events:raw"
CONSUMER_GROUP = "normalizers"

redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)


def ensure_consumer_group() -> None:
    """Creates the consumer group if it doesn't exist yet. MKSTREAM also
    creates the stream itself if this is the very first run — without it,
    XGROUP CREATE fails on a stream that doesn't exist yet."""
    try:
        redis_client.xgroup_create(
            name=STREAM_KEY, groupname=CONSUMER_GROUP, id="0", mkstream=True
        )
    except redis.ResponseError as e:
        # BUSYGROUP means the group already exists — expected on every
        # restart after the first. Anything else is a real problem.
        if "BUSYGROUP" not in str(e):
            raise
