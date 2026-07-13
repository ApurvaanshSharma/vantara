import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.alert import AlertSeverity, AlertStatus, DetectionType


class AlertOut(BaseModel):
    id: uuid.UUID
    rule_id: str
    rule_title: str
    detection_type: DetectionType
    severity: AlertSeverity
    mitre_techniques: list[str]
    source_event_id: str
    summary: str
    status: AlertStatus
    created_at: datetime

    model_config = {"from_attributes": True}


class DetectionRunResult(BaseModel):
    sigma_alerts_created: int
    correlation_alerts_created: int
    total_alerts_created: int
