"""
SQLAlchemy engine and session setup.

One engine per process (created once, at import time). Each request gets its
own Session via the get_db() dependency below — sessions are NOT thread-safe
to share across requests, which is why we create a fresh one per request
instead of reusing a global session.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
# pool_pre_ping=True: SQLAlchemy tests each connection with a lightweight query
# before handing it to a request. Without this, a connection that Postgres
# silently dropped (idle timeout, container restart) causes a confusing
# "server closed the connection unexpectedly" error on the next request that
# happens to grab it from the pool, instead of a clean reconnect.

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """All ORM models inherit from this. Alembic's env.py imports Base.metadata
    to know what tables should exist, so every new model must import this."""

    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a DB session, guarantees it's closed after
    the request finishes (success or exception) via the try/finally."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
