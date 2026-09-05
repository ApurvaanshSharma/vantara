"""
Pytest fixtures shared across the test suite.

The core pattern: each test runs inside a DB transaction that gets rolled
back afterward. Tests can freely create users, commit, query — none of it
persists once the test ends, and tests never interfere with each other's
data. This is the standard SQLAlchemy testing pattern; the alternative
(truncating tables between tests, or using a throwaway SQLite file) is
slower and, for SQLite, risks the tests passing against different SQL
semantics than what Postgres actually enforces in production.

OpenSearch is mocked at the two call sites (app.main's startup hook, and
the Celery task) rather than run for real — this test environment has no
OpenSearch instance available. Everything else (Postgres, Redis) is real.
Patch target matters here: patching app.core.opensearch_client.index_event
would NOT affect app.workers.tasks, because tasks.py already did
`from app.core.opensearch_client import index_event` — that name is now a
separate reference in tasks.py's own namespace. You have to patch it where
it's *used*, not where it's *defined*.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

import app.main as main_module
import app.workers.tasks as tasks_module
from app.core.config import settings
from app.core.database import get_db
from app.core.redis_client import STREAM_KEY, redis_client
from app.main import app
from app.workers.celery_app import celery_app

# Eager mode runs .delay() calls synchronously, in-process, instead of
# needing a real running Celery worker to consume the task from the broker.
# Standard pattern for testing Celery-based code.
celery_app.conf.update(task_always_eager=True, task_eager_propagates=True)


@pytest.fixture(scope="session", autouse=True)
def trained_ml_models():
    """Trains fresh at the start of the test session rather than assuming
    someone ran `python -m app.ml.train` first — tests should be
    self-sufficient. Training is fast (<1s, fixed seed) so retraining
    every session run costs nothing and guarantees the models under test
    match the current code, not a possibly-stale artifact from a previous
    run or a previous version of synthetic_data.py."""
    from app.ml.train import train_and_evaluate

    train_and_evaluate()


engine = create_engine(settings.database_url)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture()
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    # Standard SQLAlchemy test recipe ("joining a session into an external
    # transaction"): start a SAVEPOINT, and whenever application code calls
    # session.commit() — ending that savepoint — immediately open a new one.
    # Without this, code that legitimately needs to commit mid-test (like
    # alert_service.save_alerts, which must commit to make its own
    # savepoint-based dedup checks meaningful) would end the *outer*
    # transaction instead, and the rollback below would have nothing left
    # to undo.
    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, trans):
        nonlocal nested
        if not nested.is_active:
            nested = connection.begin_nested()

    yield session

    session.close()
    transaction.rollback()  # undoes everything the test did, including any commits
    connection.close()


@pytest.fixture(autouse=True)
def mock_opensearch(monkeypatch):
    monkeypatch.setattr(main_module, "ensure_index_template", lambda: None)

    indexed_docs = []
    monkeypatch.setattr(
        tasks_module, "index_event", lambda doc: indexed_docs.append(doc)
    )
    return indexed_docs  # tests can inspect what "would have" been indexed


@pytest.fixture(autouse=True)
def clean_redis_stream():
    """Each test gets a clean stream + consumer group — otherwise pending
    entries from one test's XADD could confuse another test's XREADGROUP."""
    redis_client.delete(STREAM_KEY)
    yield
    redis_client.delete(STREAM_KEY)


@pytest.fixture(autouse=True)
def clean_celery_session_tables():
    """Celery tasks use their own SessionLocal() (see workers/tasks.py) —
    correct in production, since a task isn't an HTTP request and has
    nothing to Depends(get_db) from. But it means alerts AND ioc_enrichments
    written during ingestion (YARA scan + its enrichment lookup) are REAL
    commits on a separate connection, invisible to and unaffected by
    db_session's transaction-rollback isolation above. Clean up explicitly,
    on a real connection, rather than assuming rollback covers it.

    Hard safety check below exists because this exact mistake already
    happened once: running `docker compose run --rm backend pytest`
    inherits the container's real DATABASE_URL — production, not a
    separate test database — and this fixture then truncated real alert
    data. Refusing to run against anything whose database name doesn't
    unambiguously say "test" makes that mistake structurally harder to
    repeat, rather than relying on remembering to pass the right env var
    every time."""
    from app.core.config import settings

    db_name = settings.database_url.rsplit("/", 1)[-1]
    if "test" not in db_name.lower():
        raise RuntimeError(
            f"Refusing to run tests against database {db_name!r} — its name "
            "doesn't contain 'test'. This fixture truncates the alerts and "
            "ioc_enrichments tables; running it against a non-test database "
            "will destroy real data. Set DATABASE_URL to a database with "
            "'test' in its name before running pytest."
        )

    from app.core.database import engine as real_engine
    from app.models.alert import Alert
    from app.models.ioc_enrichment import IOCEnrichment

    def _truncate():
        with real_engine.begin() as conn:
            conn.execute(Alert.__table__.delete())
            conn.execute(IOCEnrichment.__table__.delete())

    _truncate()
    yield
    _truncate()


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def make_user(db_session):
    """Factory for a real, persisted User row — needed anywhere a real FK
    to users.id is exercised (Case.created_by_id, Case.assigned_to_id),
    same reasoning as make_alert above."""
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    created = []

    def _make(**overrides):
        defaults = dict(
            email=f"soar-test-{len(created)}@example.com",
            hashed_password=hash_password("correcthorsebattery"),
            role=UserRole.ANALYST,
        )
        defaults.update(overrides)
        user = User(**defaults)
        db_session.add(user)
        db_session.flush()
        created.append(user)
        return user

    return _make


@pytest.fixture()
def make_alert(db_session):
    """Factory for a real, persisted Alert row — needed by any test
    exercising SOAR code, since PlaybookRun/BlockedIP have real foreign
    keys to alerts.id, not the loose string references OpenSearch-sourced
    data uses elsewhere in this project."""
    from app.models.alert import Alert, AlertSeverity, DetectionType

    created = []

    def _make(**overrides):
        defaults = dict(
            rule_id=f"test.rule.{len(created)}",
            rule_title="Test Rule",
            detection_type=DetectionType.SIGMA,
            severity=AlertSeverity.HIGH,
            mitre_techniques=["T1110"],
            source_event_id=f"evt-{len(created)}",
            summary="test alert",
            details={},
        )
        defaults.update(overrides)
        alert = Alert(**defaults)
        db_session.add(alert)
        db_session.flush()
        created.append(alert)
        return alert

    return _make
