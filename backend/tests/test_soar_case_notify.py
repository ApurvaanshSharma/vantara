import uuid

from app.models.alert import AlertSeverity
from app.models.case import Case
from app.soar import case_notify


def test_low_severity_no_case_created(db_session, make_alert, make_user):
    alert = make_alert(severity=AlertSeverity.LOW)
    result = case_notify.create_case_and_notify(db_session, alert, [], make_user().id)
    assert result["case_created"] is False
    assert db_session.query(Case).count() == 0


def test_high_severity_creates_case(db_session, make_alert, make_user, monkeypatch):
    monkeypatch.setattr(case_notify, "send_webhook", lambda payload: True)
    alert = make_alert(severity=AlertSeverity.HIGH, rule_title="Brute Force Detected")
    creator_id = make_user().id

    result = case_notify.create_case_and_notify(
        db_session, alert, ["severity:high", "mitre:T1110"], creator_id
    )

    assert result["case_created"] is True
    assert result["webhook_sent"] is True

    case = db_session.query(Case).filter_by(id=uuid.UUID(result["case_id"])).first()
    assert case is not None
    assert "Brute Force Detected" in case.title
    assert case.tags == ["severity:high", "mitre:T1110"]
    assert str(alert.id) in case.alert_ids
    assert case.created_by_id == creator_id


def test_case_still_created_when_webhook_fails(
    db_session, make_alert, make_user, monkeypatch
):
    monkeypatch.setattr(case_notify, "send_webhook", lambda payload: False)
    alert = make_alert(severity=AlertSeverity.CRITICAL)

    result = case_notify.create_case_and_notify(db_session, alert, [], make_user().id)

    assert result["case_created"] is True
    assert result["webhook_sent"] is False
