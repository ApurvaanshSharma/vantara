"""
Pydantic schemas — the API's request/response contract.

Note what's absent from UserOut: hashed_password. This is the whole reason
models and schemas are separate files (see Phase 2 notes) — it's structurally
impossible to accidentally return a password hash if the response_model
never has a field for it.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserRole


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)  # 72 = bcrypt's hard input limit


class UserOut(BaseModel):
    id: uuid.UUID
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime

    # Lets Pydantic build this model directly from a SQLAlchemy User instance
    # (reads attributes off the object) instead of requiring a dict.
    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str
