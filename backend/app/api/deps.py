"""
Shared dependencies used across route modules.

get_current_user: decodes the bearer token, loads the user from Postgres,
rejects anything invalid, expired, or the wrong token type (a refresh token
presented where an access token belongs).

require_role: a dependency *factory* — call it with the roles allowed for a
given route, and it returns a dependency FastAPI can inject. This is the seam
where the full 6-role RBAC from the original spec would plug in later:
new routes just declare `Depends(require_role([UserRole.ADMIN]))`, no changes
needed here.
"""

import uuid

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import TOKEN_TYPE_ACCESS, decode_token
from app.models.user import User, UserRole

# tokenUrl is where Swagger UI's "Authorize" button sends credentials — it's
# documentation metadata, not a redirect; the actual login logic lives in
# routes/auth.py.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.InvalidTokenError:
        raise credentials_error from None

    if payload.get("type") != TOKEN_TYPE_ACCESS:
        raise credentials_error

    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_error

    user = db.get(User, uuid.UUID(user_id))
    if user is None or not user.is_active:
        raise credentials_error

    return user


def require_role(allowed_roles: list[UserRole]):
    def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return current_user

    return _check
