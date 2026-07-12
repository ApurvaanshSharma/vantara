"""
Password hashing and JWT creation/verification.

Password hashing uses bcrypt directly (not passlib — see Phase 2 notes on why:
passlib's bcrypt backend has had version-detection breakage against recent
bcrypt releases).

JWT uses PyJWT with HS256 (a single shared secret signs and verifies tokens).
HS256 is the right call for a single backend service holding its own secret.
RS256 (asymmetric: private key signs, public key verifies) matters once
multiple independent services need to verify tokens without holding the
secret that can mint them — not a constraint this project has yet.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

import bcrypt
import jwt

from app.core.config import settings

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"


def hash_password(plain_password: str) -> str:
    """Hash a password for storage. bcrypt has a 72-byte input limit — silently
    truncating longer passwords is a real bcrypt gotcha, so we encode to bytes
    explicitly and let bcrypt raise if something upstream ever changes that."""
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def _create_token(
    subject: UUID, role: str, token_type: str, expires_delta: timedelta
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(subject),  # "subject" of the token — who it identifies
        "role": role,
        "type": token_type,  # distinguishes access vs refresh so one can't be used as the other
        "iat": now,  # issued-at
        "exp": now
        + expires_delta,  # expiry — JWT libraries reject expired tokens automatically
    }
    return jwt.encode(
        payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )


def create_access_token(subject: UUID, role: str) -> str:
    return _create_token(
        subject,
        role,
        TOKEN_TYPE_ACCESS,
        timedelta(minutes=settings.access_token_expire_minutes),
    )


def create_refresh_token(subject: UUID, role: str) -> str:
    return _create_token(
        subject,
        role,
        TOKEN_TYPE_REFRESH,
        timedelta(days=settings.refresh_token_expire_days),
    )


def decode_token(token: str) -> dict:
    """Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure —
    callers (see api/deps.py) catch these and convert to HTTP 401."""
    return jwt.decode(
        token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
    )
