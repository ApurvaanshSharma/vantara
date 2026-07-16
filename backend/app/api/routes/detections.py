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
from app.threat_intel.enrichment_service import enrich_alert_source_ip

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


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

    sigma_alert_dicts = [enrich_alert_source_ip(db, a) for a in sigma_alert_dicts]
    correlation_alert_dicts = [
        enrich_alert_source_ip(db, a) for a in correlation_alert_dicts
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
