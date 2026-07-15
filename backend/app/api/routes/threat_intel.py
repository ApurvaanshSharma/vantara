"""
On-demand IOC lookup — an analyst pasting a suspicious IP in during
investigation, not part of any automated sweep. Same cache as the
automated enrichment path in detections.py, so a manual lookup here counts
toward (and benefits from) the same 24h cache as everything else.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.schemas.ioc_enrichment import IOCLookupResult
from app.threat_intel.enrichment_service import enrich_ip
from app.threat_intel.scoring import is_enrichable_ip

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intel"])


@router.get("/{ip}", response_model=IOCLookupResult)
def lookup_ip(
    ip: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> IOCLookupResult:
    if not is_enrichable_ip(ip):
        return IOCLookupResult(indicator=ip, enrichable=False)

    enrichment = enrich_ip(db, ip)
    if enrichment is None:
        return IOCLookupResult(indicator=ip, enrichable=False)

    return IOCLookupResult(
        indicator=ip,
        enrichable=True,
        combined_threat_score=enrichment.combined_threat_score,
        abuseipdb_score=enrichment.abuseipdb_score,
        abuseipdb_total_reports=enrichment.abuseipdb_total_reports,
        otx_pulse_count=enrichment.otx_pulse_count,
        otx_malware_families=enrichment.otx_malware_families,
    )
