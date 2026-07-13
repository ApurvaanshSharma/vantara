"""
Alert persistence.

Explicit enum conversion (str value -> actual Enum member) here rather
than relying on SQLAlchemy to infer it: the Postgres enum type stores
member NAMES ('SIGMA'), while every detection engine in this phase
produces lowercase VALUES ('sigma') in its alert dicts, matching Sigma's
own `level` field convention. Converting explicitly makes that mismatch
visible in one place instead of depending on implicit behavior that would
be easy to get subtly wrong.

Dedup uses a SAVEPOINT per row (db.begin_nested()), not a full db.commit()
per row. A full commit per alert would end the caller's transaction
mid-request — the wrong granularity for "one request, one transaction" —
and, concretely, is what broke this project's own test isolation the
first time this was written: the test harness wraps each test in one
outer transaction and rolls it back at teardown, which only works if
application code never calls session.commit() itself. Savepoints let each
row's insert be individually retryable-or-skippable without ending
anything the caller (a request, a Celery task, a test) is relying on.
"""

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertSeverity, DetectionType


def save_alerts(db: Session, alert_dicts: list[dict]) -> int:
    saved = 0
    for data in alert_dicts:
        alert = Alert(
            rule_id=data["rule_id"],
            rule_title=data["rule_title"],
            detection_type=DetectionType(data["detection_type"]),
            severity=AlertSeverity(data["severity"]),
            mitre_techniques=data["mitre_techniques"],
            source_event_id=data["source_event_id"],
            summary=data["summary"],
            details=data.get("details", {}),
        )
        try:
            with db.begin_nested():  # SAVEPOINT — scoped to this one row
                db.add(alert)
                db.flush()  # sends the INSERT now, so a unique-constraint
                # violation raises here, inside the savepoint, instead of
                # waiting for a later flush/commit to discover it.
            saved += 1
        except IntegrityError:
            pass  # already exists for this (rule_id, source_event_id) — expected, not an error

    db.commit()  # one commit for the whole batch, at the caller's transaction boundary
    return saved
