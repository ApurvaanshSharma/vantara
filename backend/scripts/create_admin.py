"""
Promote an existing user to ADMIN. Run manually — never exposed via the API.

Usage (from backend/, with the venv or container's Python):
    python -m scripts.create_admin user@example.com

The user must already exist (register via POST /api/v1/auth/register first).
This script only flips their role — it deliberately does not create users
from scratch, so there's always an auditable "who registered this account"
trail even for admins.
"""

import sys

from app.core.database import SessionLocal
from app.models.user import User, UserRole


def promote_to_admin(email: str) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            print(f"No user found with email: {email}")
            sys.exit(1)
        user.role = UserRole.ADMIN
        db.commit()
        print(f"{email} is now an admin.")
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.create_admin <email>")
        sys.exit(1)
    promote_to_admin(sys.argv[1])
