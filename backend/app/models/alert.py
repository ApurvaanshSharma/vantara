"""
The Alert table — what every detection mechanism in this phase produces,
regardless of whether it came from a Sigma rule, the brute-force
correlation check, or a real-time YARA match.

The (rule_id, source_event_id) unique constraint is what makes re-running
detection safe: Sigma and correlation both run on overlapping time windows
by design (see detection/sigma_engine.py and detection/correlation.py for
why), so the same match would otherwise generate duplicate alerts every run.
The constraint pushes dedup down to the database instead of requiring
correct bookkeeping in every detection mechanism that writes here.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class DetectionType(str, enum.Enum):
    SIGMA = "sigma"
    CORRELATION = "correlation"
    YARA = "yara"


class AlertSeverity(str, enum.Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("rule_id", "source_event_id", name="uq_alert_rule_event"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_title: Mapped[str] = mapped_column(String(255), nullable=False)
    detection_type: Mapped[DetectionType] = mapped_column(
        Enum(DetectionType, name="detection_type"), nullable=False
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"), nullable=False
    )
    # Empty list, not null, when a rule has no MITRE mapping — see
    # detection/sigma_rules/firewall_block.yml for why that's a deliberate
    # choice on some rules, not an oversight.
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    # For Sigma/YARA: the actual OpenSearch event_id that matched.
    # For correlation: a synthetic key (e.g. "bruteforce:<ip>:<hour>") —
    # there's no single triggering event, so the dedup key is constructed
    # instead of borrowed. See detection/correlation.py.
    source_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"), nullable=False, default=AlertStatus.NEW
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
