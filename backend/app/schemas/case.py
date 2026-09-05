import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.alert import AlertSeverity
from app.models.case import CaseStatus


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    summary: str = ""
    severity: AlertSeverity
    tags: list[str] = []
    alert_ids: list[str] = []


class CaseUpdate(BaseModel):
    status: CaseStatus | None = None
    assigned_to_id: uuid.UUID | None = None
    tags: list[str] | None = None


class CaseCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class CaseCommentOut(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    user_id: uuid.UUID
    body: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CaseOut(BaseModel):
    id: uuid.UUID
    title: str
    summary: str
    status: CaseStatus
    severity: AlertSeverity
    tags: list[str]
    alert_ids: list[str]
    assigned_to_id: uuid.UUID | None
    created_by_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None

    model_config = {"from_attributes": True}
