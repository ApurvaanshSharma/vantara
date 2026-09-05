from app.models.alert import AlertSeverity
from app.models.soar import BlockedIP
from app.soar.ip_block import block_ip_if_applicable


def test_low_severity_not_blocked(db_session, make_alert):
    alert = make_alert(severity=AlertSeverity.LOW, details={"source_ip": "118.25.6.39"})
    result = block_ip_if_applicable(db_session, alert)
    assert result["blocked"] is False
    assert "severity" in result["reason"]


def test_high_severity_with_source_ip_gets_blocked(db_session, make_alert):
    alert = make_alert(
        severity=AlertSeverity.HIGH, details={"source_ip": "118.25.6.39"}
    )
    result = block_ip_if_applicable(db_session, alert)
    assert result["blocked"] is True
    assert result["ip_address"] == "118.25.6.39"
    assert result["already_blocked"] is False

    row = db_session.query(BlockedIP).filter_by(ip_address="118.25.6.39").first()
    assert row is not None
    assert row.alert_id == alert.id


def test_no_source_ip_not_blocked(db_session, make_alert):
    alert = make_alert(severity=AlertSeverity.CRITICAL, details={})
    result = block_ip_if_applicable(db_session, alert)
    assert result["blocked"] is False
    assert "source_ip" in result["reason"]


def test_source_ip_from_nested_matched_event(db_session, make_alert):
    alert = make_alert(
        severity=AlertSeverity.HIGH,
        details={"matched_event": {"source_ip": "203.0.113.5"}},
    )
    result = block_ip_if_applicable(db_session, alert)
    assert result["blocked"] is True
    assert result["ip_address"] == "203.0.113.5"


def test_already_blocked_ip_not_duplicated(db_session, make_alert):
    alert1 = make_alert(
        severity=AlertSeverity.HIGH, details={"source_ip": "118.25.6.39"}
    )
    block_ip_if_applicable(db_session, alert1)

    alert2 = make_alert(
        severity=AlertSeverity.CRITICAL, details={"source_ip": "118.25.6.39"}
    )
    result = block_ip_if_applicable(db_session, alert2)

    assert result["already_blocked"] is True
    assert db_session.query(BlockedIP).filter_by(ip_address="118.25.6.39").count() == 1
