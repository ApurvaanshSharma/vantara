"""
Playbook 2: simulated IP block.

"Simulated" is the accurate word, not a hedge: this writes a row to
blocked_ips, it does not touch a real firewall, iptables, or any network
device. Actually blocking traffic needs infrastructure this project
doesn't have (a firewall API, an EDR agent, or at minimum a host this
platform controls) — named as an explicit scope cut back at the very
start of this project. What this DOES demonstrate genuinely: the
decision logic (which alerts warrant a block, deduping repeat blocks of
the same IP) that a real integration would sit behind.
"""

from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertSeverity
from app.models.soar import BlockedIP

BLOCK_SEVERITIES = {AlertSeverity.HIGH, AlertSeverity.CRITICAL}


def _extract_source_ip(alert: Alert) -> str | None:
    return alert.details.get("source_ip") or alert.details.get("matched_event", {}).get(
        "source_ip"
    )


def block_ip_if_applicable(db: Session, alert: Alert) -> dict:
    if alert.severity not in BLOCK_SEVERITIES:
        return {"blocked": False, "reason": "severity below block threshold"}

    ip = _extract_source_ip(alert)
    if not ip:
        return {"blocked": False, "reason": "alert has no source_ip to block"}

    existing = db.query(BlockedIP).filter_by(ip_address=ip).first()
    if existing:
        return {"blocked": True, "ip_address": ip, "already_blocked": True}

    blocked = BlockedIP(
        ip_address=ip, reason=f"Auto-blocked: {alert.rule_title}", alert_id=alert.id
    )
    db.add(blocked)
    db.flush()
    return {"blocked": True, "ip_address": ip, "already_blocked": False}
