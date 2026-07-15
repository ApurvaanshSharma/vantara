"""
Enrichment orchestration: cache-first, real API calls only on a genuine
miss or an expired entry.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.ioc_enrichment import IOCEnrichment
from app.threat_intel import abuseipdb_client, otx_client
from app.threat_intel.scoring import compute_combined_score, is_enrichable_ip

CACHE_TTL_HOURS = 24
# A genuinely "checked, nothing found" result is safe to trust for a full
# day. A result where a source returned nothing at all (rate limit, bad
# key, network error, etc.) is NOT the same thing as "confirmed clean" —
# caching that for 24h would mean a transient failure looks identical to a
# clean IP for the rest of the day, even after whatever caused the
# failure is fixed. Retry those much sooner instead.
FAILED_LOOKUP_RETRY_MINUTES = 10


def _is_fresh(enrichment: IOCEnrichment) -> bool:
    age = datetime.now(timezone.utc) - enrichment.fetched_at
    # otx_pulse_count is None specifically when otx_data was None (the
    # call failed) — 0 is a real, successful "no pulses found" answer.
    # abuseipdb_score is None under the same failure condition. Either
    # being None means at least one source didn't actually get checked.
    had_a_failure = (
        enrichment.abuseipdb_score is None or enrichment.otx_pulse_count is None
    )
    if had_a_failure:
        return age < timedelta(minutes=FAILED_LOOKUP_RETRY_MINUTES)
    return age < timedelta(hours=CACHE_TTL_HOURS)


def enrich_ip(db: Session, ip: str) -> IOCEnrichment | None:
    """Returns None for non-enrichable IPs (private/reserved/invalid) —
    a deliberate no-op, not an error. Otherwise always returns a row,
    served from cache when fresh."""
    if not is_enrichable_ip(ip):
        return None

    existing = (
        db.query(IOCEnrichment)
        .filter_by(indicator_type="ip", indicator_value=ip)
        .first()
    )
    if existing and _is_fresh(existing):
        return existing

    abuseipdb_data = abuseipdb_client.check_ip(ip)
    otx_data = otx_client.check_ip(ip)
    combined_score = compute_combined_score(abuseipdb_data, otx_data)

    otx_pulse_info = (otx_data or {}).get("pulse_info", {})
    malware_families = sorted(
        {
            family
            for pulse in otx_pulse_info.get("pulses", [])
            for family in pulse.get("malware_families", [])
        }
    )

    if existing is None:
        existing = IOCEnrichment(indicator_type="ip", indicator_value=ip)
        db.add(existing)

    existing.abuseipdb_score = (
        abuseipdb_data.get("abuseConfidenceScore") if abuseipdb_data else None
    )
    existing.abuseipdb_total_reports = (
        abuseipdb_data.get("totalReports") if abuseipdb_data else None
    )
    existing.otx_pulse_count = otx_pulse_info.get("count")
    existing.otx_malware_families = malware_families
    existing.combined_threat_score = combined_score
    existing.raw_abuseipdb = abuseipdb_data
    existing.raw_otx = otx_data
    existing.fetched_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(existing)
    return existing


def enrichment_summary(enrichment: IOCEnrichment | None) -> dict | None:
    """Compact form suitable for embedding in an alert's `details` field —
    the full raw_abuseipdb/raw_otx blobs stay in the ioc_enrichments table,
    not duplicated into every alert that references the same IP."""
    if enrichment is None:
        return None
    return {
        "indicator": enrichment.indicator_value,
        "combined_threat_score": enrichment.combined_threat_score,
        "abuseipdb_score": enrichment.abuseipdb_score,
        "otx_pulse_count": enrichment.otx_pulse_count,
        "otx_malware_families": enrichment.otx_malware_families,
    }
