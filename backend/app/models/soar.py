"""
SOAR models.

BlockedIP is explicitly a table, not a firewall rule — see soar/ip_block.py
for why "simulated" is the correct word, not a hedge. PlaybookRun's unique
constraint on (playbook_name, alert_id) is the dedup mechanism for
/soar/run, same pattern as Alert's (rule_id, source_event_id): re-running
the sweep over an overlapping window shouldn't re-execute a playbook that
already ran for a given alert.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PlaybookName(str, enum.Enum):
    AUTO_TAG = "auto_tag"
    SIMULATED_IP_BLOCK = "simulated_ip_block"
    AUTO_CASE_NOTIFY = "auto_case_notify"


class PlaybookRunStatus(str, enum.Enum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ip_address: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False
    )
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (
        UniqueConstraint("playbook_name", "alert_id", name="uq_playbook_alert"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    playbook_name: Mapped[PlaybookName] = mapped_column(
        Enum(PlaybookName, name="playbook_name"), nullable=False
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False
    )
    status: Mapped[PlaybookRunStatus] = mapped_column(
        Enum(PlaybookRunStatus, name="playbook_run_status"), nullable=False
    )
    result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
