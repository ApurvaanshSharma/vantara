import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.soar import PlaybookName, PlaybookRunStatus


class PlaybookRunOut(BaseModel):
    id: uuid.UUID
    playbook_name: PlaybookName
    alert_id: uuid.UUID
    status: PlaybookRunStatus
    result: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class SoarRunResult(BaseModel):
    alerts_processed: int
    total_playbook_runs: int


class BlockedIPOut(BaseModel):
    id: uuid.UUID
    ip_address: str
    reason: str
    alert_id: uuid.UUID
    blocked_at: datetime

    model_config = {"from_attributes": True}
