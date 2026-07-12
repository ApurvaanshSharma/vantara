"""
The User table — the only table Phase 2 introduces.

RBAC is deliberately minimal here: an Enum column with two values. This is
the extensible seam the original spec's 6-role RBAC would grow from later
(more roles = more Enum values + more granular permission checks in
api/deps.py) — not a redesign, just an extension point.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"


class User(Base):
    __tablename__ = "users"

    # UUID primary key generated in Python (uuid.uuid4), not by Postgres
    # (which would need the pgcrypto extension enabled for gen_random_uuid()).
    # Fewer moving parts for a solo project's first migration.
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"), nullable=False, default=UserRole.ANALYST
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
