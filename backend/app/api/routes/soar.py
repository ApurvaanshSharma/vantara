"""
SOAR routes. /run follows the same explicit-trigger pattern as
/detections/run and /ml/score — see those files' notes on why (no Celery
Beat yet, named as a real gap rather than hidden).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.alert import Alert, AlertStatus
from app.models.soar import BlockedIP, PlaybookRun
from app.models.user import User
from app.schemas.soar import BlockedIPOut, PlaybookRunOut, SoarRunResult
from app.soar.orchestrator import run_playbooks_for_alert

router = APIRouter(prefix="/api/v1/soar", tags=["soar"])


@router.post("/run", response_model=SoarRunResult)
def run_soar(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SoarRunResult:
    alerts = (
        db.query(Alert)
        .filter(Alert.status == AlertStatus.NEW)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )

    total_runs = 0
    for alert in alerts:
        runs = run_playbooks_for_alert(db, alert, current_user.id)
        total_runs += len(runs)

    return SoarRunResult(alerts_processed=len(alerts), total_playbook_runs=total_runs)


@router.get("/runs", response_model=list[PlaybookRunOut])
def list_playbook_runs(
    limit: int = 100,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[PlaybookRun]:
    return (
        db.query(PlaybookRun).order_by(PlaybookRun.created_at.desc()).limit(limit).all()
    )


@router.get("/blocked-ips", response_model=list[BlockedIPOut])
def list_blocked_ips(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[BlockedIP]:
    return db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
