"""
Detection routes.

/run triggers Sigma + correlation sweeps synchronously and returns counts —
deliberately not a background task. A production system would run this on
a schedule (Celery Beat) independent of anyone calling an endpoint; for
this phase, an explicit trigger is simpler to test and demonstrate, with
the scheduling gap named rather than silently papered over.
YARA alerts don't appear here — they're created in real time during
ingestion (see workers/tasks.py) and show up in GET /alerts immediately,
no trigger needed.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.detection.alert_service import save_alerts
from app.detection.correlation import run_bruteforce_detection
from app.detection.sigma_engine import run_sigma_detection
from app.models.alert import Alert, AlertStatus
from app.models.user import User
from app.schemas.alert import AlertOut, DetectionRunResult
from app.threat_intel.enrichment_service import enrich_ip, enrichment_summary

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


def _enrich_alert_source_ip(db: Session, alert: dict) -> dict:
    """Looks for a source_ip in the two places this phase's alert dicts put
    it — correlation's top-level details.source_ip, or Sigma's nested
    details.matched_event.source_ip — and attaches an enrichment summary
    if found. Silently leaves the alert unchanged if there's no IP to
    enrich (e.g. the firewall Sigma rule's matched_event might not have
    one, or the IP is private/reserved) — enrichment is additive, never
    required for an alert to be valid."""
    source_ip = alert["details"].get("source_ip") or alert["details"].get(
        "matched_event", {}
    ).get("source_ip")
    if not source_ip:
        return alert

    enrichment = enrich_ip(db, source_ip)
    summary = enrichment_summary(enrichment)
    if summary:
        alert["details"]["threat_intel"] = summary
    return alert


@router.post("/run", response_model=DetectionRunResult)
def run_detection(
    lookback_minutes: int = 20,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> DetectionRunResult:
    sigma_alert_dicts = run_sigma_detection(lookback_minutes=lookback_minutes)
    correlation_alert_dicts = run_bruteforce_detection(
        lookback_minutes=lookback_minutes
    )

    sigma_alert_dicts = [_enrich_alert_source_ip(db, a) for a in sigma_alert_dicts]
    correlation_alert_dicts = [
        _enrich_alert_source_ip(db, a) for a in correlation_alert_dicts
    ]

    sigma_saved = save_alerts(db, sigma_alert_dicts)
    correlation_saved = save_alerts(db, correlation_alert_dicts)

    return DetectionRunResult(
        sigma_alerts_created=sigma_saved,
        correlation_alerts_created=correlation_saved,
        total_alerts_created=sigma_saved + correlation_saved,
    )


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[Alert]:
    query = db.query(Alert)
    if status_filter is not None:
        query = query.filter(Alert.status == status_filter)
    return query.order_by(Alert.created_at.desc()).limit(limit).all()
