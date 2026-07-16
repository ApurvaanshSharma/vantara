"""
ML routes.

/score follows the same explicit-trigger pattern as /detections/run — see
that file's notes on why (no Celery Beat yet, a real gap named rather than
hidden). Scans recently-active source_ips, scores each, creates alerts for
anomalies, enriches with threat intel exactly like every other detection
mechanism.
"""

import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.detection.alert_service import save_alerts
from app.ml.alerting import build_ml_alert_dict
from app.ml.features import extract_features, get_recent_active_ips
from app.ml.inference import score_features
from app.ml.model_store import METRICS_PATH
from app.ml.train import train_and_evaluate
from app.models.user import User
from app.schemas.ml import MLScoreResult, TrainResult
from app.threat_intel.enrichment_service import enrich_alert_source_ip

router = APIRouter(prefix="/api/v1/ml", tags=["ml"])


@router.post("/train", response_model=TrainResult)
def train(_current_user: User = Depends(get_current_user)) -> TrainResult:
    metrics = train_and_evaluate()
    return TrainResult(**metrics)


@router.get("/metrics", response_model=TrainResult)
def get_metrics(_current_user: User = Depends(get_current_user)) -> TrainResult:
    if not METRICS_PATH.exists():
        # Train once on first request rather than erroring — a fresh
        # deployment shouldn't require someone to remember a manual step
        # before this endpoint is useful.
        metrics = train_and_evaluate()
    else:
        metrics = json.loads(METRICS_PATH.read_text())
    return TrainResult(**metrics)


@router.post("/score", response_model=MLScoreResult)
def score(
    lookback_minutes: int = 60,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> MLScoreResult:
    active_ips = get_recent_active_ips(lookback_minutes=lookback_minutes)
    alert_dicts = []

    for ip in active_ips:
        features = extract_features(ip, lookback_minutes=lookback_minutes)
        result = score_features(features)
        if result.get("is_anomalous"):
            alert_dict = build_ml_alert_dict(ip, features, result)
            alert_dict = enrich_alert_source_ip(db, alert_dict)
            alert_dicts.append(alert_dict)

    saved = save_alerts(db, alert_dicts)
    return MLScoreResult(ips_scanned=len(active_ips), alerts_created=saved)
