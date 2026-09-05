"""
Orchestrator: runs all 3 playbooks for one alert, in a fixed order.

Idempotency is per-playbook, not per-sweep: if /soar/run is called twice
over an overlapping window (same pattern as detections.py's lookback
windows), a playbook that already ran for a given alert is NOT re-run —
its existing PlaybookRun row is returned instead. This matters more here
than for Sigma/correlation dedup: re-running auto_case_notify wouldn't
just create a noisy duplicate alert, it would send a second webhook and
create a second case for the same incident.
"""

import uuid

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.soar import PlaybookName, PlaybookRun, PlaybookRunStatus
from app.soar.auto_tag import compute_tags
from app.soar.case_notify import create_case_and_notify
from app.soar.ip_block import block_ip_if_applicable


def _get_or_run(
    db: Session, playbook_name: PlaybookName, alert: Alert, action
) -> PlaybookRun:
    existing = (
        db.query(PlaybookRun)
        .filter_by(playbook_name=playbook_name, alert_id=alert.id)
        .first()
    )
    if existing:
        return existing

    status, result = action()
    run = PlaybookRun(
        playbook_name=playbook_name, alert_id=alert.id, status=status, result=result
    )
    db.add(run)
    db.flush()
    return run


def run_playbooks_for_alert(
    db: Session, alert: Alert, triggering_user_id: uuid.UUID
) -> list[PlaybookRun]:
    tags = compute_tags(alert)  # computed once, reused by auto_case_notify below

    run1 = _get_or_run(
        db,
        PlaybookName.AUTO_TAG,
        alert,
        lambda: (PlaybookRunStatus.SUCCESS, {"tags": tags}),
    )

    def _run_ip_block():
        result = block_ip_if_applicable(db, alert)
        status = (
            PlaybookRunStatus.SUCCESS
            if result["blocked"]
            else PlaybookRunStatus.SKIPPED
        )
        return status, result

    run2 = _get_or_run(db, PlaybookName.SIMULATED_IP_BLOCK, alert, _run_ip_block)

    def _run_case_notify():
        result = create_case_and_notify(db, alert, tags, triggering_user_id)
        status = (
            PlaybookRunStatus.SUCCESS
            if result["case_created"]
            else PlaybookRunStatus.SKIPPED
        )
        return status, result

    run3 = _get_or_run(db, PlaybookName.AUTO_CASE_NOTIFY, alert, _run_case_notify)

    db.commit()
    return [run1, run2, run3]
