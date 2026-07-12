"""
Auth routes.

Note that /register always creates an ANALYST. There is deliberately no way
to self-register as admin through the API — privilege escalation must never
be a public, unauthenticated action. The first admin is created via
scripts/create_admin.py (see Phase 2 notes) — a deliberate manual step, not
an oversight.
"""

import uuid

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.core.security import (
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User, UserRole
from app.schemas.user import RefreshRequest, Token, UserCreate, UserOut

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=UserRole.ANALYST,
    )
    db.add(user)
    db.commit()
    db.refresh(user)  # loads server-generated fields (created_at) back onto the object
    return user


@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
) -> Token:
    # OAuth2PasswordRequestForm names the field "username" even though we're
    # treating it as an email — this is the standard OAuth2 password-grant
    # shape FastAPI's Swagger UI expects, not a design choice specific to us.
    user = db.query(User).filter(User.email == form_data.username).first()
    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise invalid_credentials
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled"
        )

    return Token(
        access_token=create_access_token(user.id, user.role.value),
        refresh_token=create_refresh_token(user.id, user.role.value),
    )


@router.post("/refresh", response_model=Token)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> Token:
    invalid_token = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )
    try:
        decoded = decode_token(payload.refresh_token)
    except jwt.PyJWTError:
        raise invalid_token from None

    if decoded.get("type") != TOKEN_TYPE_REFRESH:
        raise invalid_token

    try:
        user_id = uuid.UUID(decoded["sub"])
    except (KeyError, ValueError):
        raise invalid_token from None

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise invalid_token

    # Only a new access token is issued — the original refresh token stays
    # valid until its own expiry. Rotating refresh tokens on every use (and
    # revoking the old one) is a real hardening step worth naming in an
    # interview as a deliberate v1 vs v2 trade-off, not something we didn't
    # know about.
    return Token(
        access_token=create_access_token(user.id, user.role.value),
        refresh_token=payload.refresh_token,
    )


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.get("/admin-check")
def admin_check(current_user: User = Depends(require_role([UserRole.ADMIN]))) -> dict:
    """Demonstrates RBAC actually blocks non-admins — not just that the
    dependency exists, but that a real analyst-role token gets a 403 here."""
    return {"message": f"Welcome, admin {current_user.email}"}
