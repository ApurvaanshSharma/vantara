"""
IOC enrichment cache.

Why this table exists at all: AbuseIPDB's free tier allows 1,000 checks/day
— easy to burn through in minutes if the same source_ip (which recurs
across many alerts, e.g. every event in a brute-force burst) triggers a
fresh API call every time. Caching by (indicator_type, indicator_value)
with a TTL means one real API call per IP per CACHE_TTL_HOURS, no matter
how many alerts reference it.
"""

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"
    __table_args__ = (
        UniqueConstraint("indicator_type", "indicator_value", name="uq_ioc_type_value"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    indicator_type: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # "ip" for now
    indicator_value: Mapped[str] = mapped_column(String(255), nullable=False)

    abuseipdb_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    abuseipdb_total_reports: Mapped[int | None] = mapped_column(Integer, nullable=True)
    otx_pulse_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    otx_malware_families: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)

    combined_threat_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    raw_abuseipdb: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    raw_otx: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
