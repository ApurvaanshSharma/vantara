"""
Playbook 3: auto-case + notify. The only playbook with a real external
side effect (the webhook) — deliberately still creates the case even if
webhook delivery fails, since a notification is a nice-to-have on top of
the case, not a precondition for it.
"""

import uuid

from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertSeverity
from app.models.case import Case, CaseStatus
from app.soar.webhook_client import send_webhook

CASE_SEVERITIES = {AlertSeverity.HIGH, AlertSeverity.CRITICAL}


def create_case_and_notify(
    db: Session, alert: Alert, tags: list[str], created_by_id: uuid.UUID
) -> dict:
    if alert.severity not in CASE_SEVERITIES:
        return {
            "case_created": False,
            "reason": "severity below case-creation threshold",
        }

    case = Case(
        title=f"{alert.rule_title} — {alert.summary[:80]}",
        summary=alert.summary,
        status=CaseStatus.OPEN,
        severity=alert.severity,
        tags=tags,
        alert_ids=[str(alert.id)],
        created_by_id=created_by_id,
    )
    db.add(case)
    db.flush()  # need case.id before building the webhook payload

    webhook_sent = send_webhook(
        {
            "event": "case_created",
            "case_id": str(case.id),
            "title": case.title,
            "severity": case.severity.value,
            "tags": tags,
        }
    )

    return {"case_created": True, "case_id": str(case.id), "webhook_sent": webhook_sent}
