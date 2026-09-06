from app.models.alert import AlertSeverity
from app.models.soar import PlaybookName, PlaybookRun, PlaybookRunStatus
from app.soar import case_notify, orchestrator


def test_all_three_playbooks_run_for_high_severity_alert(
    db_session, make_alert, make_user, monkeypatch
):
    monkeypatch.setattr(case_notify, "send_webhook", lambda payload: True)
    alert = make_alert(
        severity=AlertSeverity.HIGH,
        mitre_techniques=["T1110"],
        details={"source_ip": "118.25.6.39"},
    )

    runs = orchestrator.run_playbooks_for_alert(db_session, alert, make_user().id)

    assert len(runs) == 3
    by_name = {r.playbook_name: r for r in runs}
    assert by_name[PlaybookName.AUTO_TAG].status == PlaybookRunStatus.SUCCESS
    assert by_name[PlaybookName.SIMULATED_IP_BLOCK].status == PlaybookRunStatus.SUCCESS
    assert by_name[PlaybookName.AUTO_CASE_NOTIFY].status == PlaybookRunStatus.SUCCESS


def test_low_severity_alert_skips_block_and_case(db_session, make_alert, make_user):
    alert = make_alert(severity=AlertSeverity.LOW, details={"source_ip": "118.25.6.39"})

    runs = orchestrator.run_playbooks_for_alert(db_session, alert, make_user().id)

    by_name = {r.playbook_name: r for r in runs}
    assert (
        by_name[PlaybookName.AUTO_TAG].status == PlaybookRunStatus.SUCCESS
    )  # always runs
    assert by_name[PlaybookName.SIMULATED_IP_BLOCK].status == PlaybookRunStatus.SKIPPED
    assert by_name[PlaybookName.AUTO_CASE_NOTIFY].status == PlaybookRunStatus.SKIPPED


def test_rerunning_same_alert_does_not_duplicate_or_resend_webhook(
    db_session, make_alert, make_user, monkeypatch
):
    webhook_calls = {"count": 0}

    def fake_webhook(payload):
        webhook_calls["count"] += 1
        return True

    monkeypatch.setattr(case_notify, "send_webhook", fake_webhook)
    alert = make_alert(
        severity=AlertSeverity.CRITICAL, details={"source_ip": "118.25.6.39"}
    )

    orchestrator.run_playbooks_for_alert(db_session, alert, make_user().id)
    orchestrator.run_playbooks_for_alert(
        db_session, alert, make_user().id
    )  # simulates overlapping sweep

    assert webhook_calls["count"] == 1  # NOT 2 — the whole point of the dedup
    assert (
        db_session.query(PlaybookRun)
        .filter_by(playbook_name=PlaybookName.AUTO_CASE_NOTIFY, alert_id=alert.id)
        .count()
        == 1
    )
