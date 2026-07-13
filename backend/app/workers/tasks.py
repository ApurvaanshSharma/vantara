"""
The one background task in Phase 3/4: drain pending Stream entries,
normalize each, YARA-scan the message text, index to OpenSearch, acknowledge.

YARA runs here (real-time, per event) rather than as a periodic sweep like
Sigma/correlation — it's a cheap string match against one message, not a
query across many indexed events, so there's no reason to delay it.

Known gap, stated deliberately rather than hidden: if a worker crashes
between reading an entry and XACK-ing it, that entry stays "pending" under
a consumer name tied to a process that no longer exists — nothing currently
reclaims it. The real fix is a periodic XAUTOCLAIM sweep for entries pending
longer than some threshold, handed to a dead consumer. Correct behavior for
Phase 3's purpose (prove the pipeline works); worth naming as the next
hardening step, not something overlooked.
"""

import json
import logging
import os

from app.core.database import SessionLocal
from app.core.normalization import NormalizationError, normalize
from app.core.opensearch_client import index_event
from app.core.redis_client import (
    CONSUMER_GROUP,
    STREAM_KEY,
    ensure_consumer_group,
    redis_client,
)
from app.detection.alert_service import save_alerts
from app.detection.yara_engine import (
    load_yara_rules,
    scan_message,
    yara_match_to_alert_dict,
)
from app.schemas.event import RawEventIn
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# Compiled once at import time (see yara_engine.py docstring) — not per task
# invocation, not per event.
_yara_rules = load_yara_rules()


@celery_app.task(name="process_stream_batch")
def process_stream_batch(batch_size: int = 50) -> int:
    ensure_consumer_group()
    consumer_name = f"worker-{os.getpid()}"

    response = redis_client.xreadgroup(
        groupname=CONSUMER_GROUP,
        consumername=consumer_name,
        streams={
            STREAM_KEY: ">"
        },  # ">" = only entries never delivered to this group before
        count=batch_size,
        block=1000,
    )
    if not response:
        return 0

    processed = 0
    db = SessionLocal()
    try:
        for _stream_key, entries in response:
            for entry_id, fields in entries:
                try:
                    raw_event = RawEventIn(
                        source_type=fields["source_type"],
                        payload=json.loads(fields["payload_json"]),
                    )
                    normalized = normalize(raw_event)
                    index_event(normalized.to_opensearch_doc())

                    matches = scan_message(_yara_rules, normalized.message)
                    if matches:
                        alert_dicts = [
                            yara_match_to_alert_dict(
                                str(normalized.event_id), normalized.message, match
                            )
                            for match in matches
                        ]
                        save_alerts(db, alert_dicts)
                except NormalizationError as e:
                    # Malformed event: log and move on. Acknowledging it anyway
                    # is deliberate — without a dead-letter index (a real v2
                    # addition), retrying a permanently-malformed event forever
                    # is worse than losing that one event and logging why.
                    logger.warning("Dropping unparseable event %s: %s", entry_id, e)
                except Exception:
                    logger.exception("Unexpected error processing event %s", entry_id)
                    continue  # do NOT ack — leave it pending for retry/investigation

                redis_client.xack(STREAM_KEY, CONSUMER_GROUP, entry_id)
                processed += 1
    finally:
        db.close()

    return processed
