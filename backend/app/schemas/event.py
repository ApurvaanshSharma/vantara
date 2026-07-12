"""
Event schemas.

RawEventIn: what the ingest API accepts — deliberately loose (payload is
free-form dict) because different log sources have wildly different shapes.
source_type tells the normalizer which parser to use.

NormalizedEvent: what every source, regardless of original shape, becomes.
This is the schema Phase 4's Sigma rules and dashboards will actually query
against — the entire point of normalization is that a Sigma rule matching
"failed login from a given IP" works the same whether the event originally
came from a Linux auth log or a firewall JSON blob.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

SourceType = Literal["generic_json", "linux_auth", "firewall_json"]


class RawEventIn(BaseModel):
    source_type: SourceType
    payload: Any  # dict for JSON sources, raw string for linux_auth lines


class NormalizedEvent(BaseModel):
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_timestamp: datetime
    source_type: SourceType
    host: str | None = None
    severity: Literal["info", "warning", "critical"] = "info"
    action: str | None = None  # e.g. "login_failed", "connection_blocked"
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    message: str
    raw: Any  # original payload, preserved for drill-down / forensics

    def to_opensearch_doc(self) -> dict:
        doc = self.model_dump(mode="json")
        doc["event_id"] = str(self.event_id)
        return doc
