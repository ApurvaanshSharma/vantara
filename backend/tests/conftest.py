"""
Pytest fixtures shared across the test suite.

The core pattern: each test runs inside a DB transaction that gets rolled
back afterward. Tests can freely create users, commit, query — none of it
persists once the test ends, and tests never interfere with each other's
data. This is the standard SQLAlchemy testing pattern; the alternative
(truncating tables between tests, or using a throwaway SQLite file) is
slower and, for SQLite, risks the tests passing against different SQL
semantics than what Postgres actually enforces in production.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.main import app

engine = create_engine(settings.database_url)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture()
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()  # undoes everything the test did, including commits
    connection.close()


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
