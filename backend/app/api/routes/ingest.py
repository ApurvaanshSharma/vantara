"""
Ingest route — the front door for log sources.

Returns 202 Accepted, not 200/201: the event is durably queued, not yet
processed. This is the correct status code for "I've accepted this and
will act on it asynchronously" — the caller shouldn't assume the event is
searchable in OpenSearch the instant this response comes back.
"""

import json

from fastapi import APIRouter, Depends, status

from app.api.deps import verify_ingest_key
from app.core.redis_client import STREAM_KEY, redis_client
from app.schemas.event import RawEventIn
from app.workers.tasks import process_stream_batch

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


@router.post(
    "/events",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_ingest_key)],
)
def ingest_event(event: RawEventIn) -> dict:
    entry_id = redis_client.xadd(
        STREAM_KEY,
        {"source_type": event.source_type, "payload_json": json.dumps(event.payload)},
    )
    # Fire-and-forget nudge — even if this particular call is somehow lost,
    # the event is already durably in the Stream; a later nudge (or a
    # future periodic sweep) still finds and processes it.
    process_stream_batch.delay()
    return {"status": "accepted", "stream_entry_id": entry_id}
