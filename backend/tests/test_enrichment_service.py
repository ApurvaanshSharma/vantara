from app.models.ioc_enrichment import IOCEnrichment
from app.threat_intel import enrichment_service


def test_enrich_ip_skips_non_enrichable(db_session):
    result = enrichment_service.enrich_ip(db_session, "10.0.0.5")
    assert result is None
    assert db_session.query(IOCEnrichment).count() == 0


def test_enrich_ip_calls_apis_and_caches(db_session, monkeypatch):
    calls = {"abuseipdb": 0, "otx": 0}

    def fake_abuseipdb(ip):
        calls["abuseipdb"] += 1
        return {"abuseConfidenceScore": 80, "totalReports": 5}

    def fake_otx(ip):
        calls["otx"] += 1
        return {"pulse_info": {"count": 2, "pulses": [{"malware_families": ["Mirai"]}]}}

    monkeypatch.setattr(enrichment_service.abuseipdb_client, "check_ip", fake_abuseipdb)
    monkeypatch.setattr(enrichment_service.otx_client, "check_ip", fake_otx)

    result = enrichment_service.enrich_ip(db_session, "118.25.6.39")

    assert result is not None
    assert result.abuseipdb_score == 80
    assert result.otx_pulse_count == 2
    assert result.otx_malware_families == ["Mirai"]
    assert result.combined_threat_score == 60  # 0.6*80 + 0.4*30 = 48+12=60
    assert calls["abuseipdb"] == 1
    assert calls["otx"] == 1


def test_enrich_ip_second_call_uses_cache_not_apis(db_session, monkeypatch):
    calls = {"abuseipdb": 0, "otx": 0}

    def fake_abuseipdb(ip):
        calls["abuseipdb"] += 1
        return {"abuseConfidenceScore": 50}

    def fake_otx(ip):
        calls["otx"] += 1
        return {"pulse_info": {"count": 0}}

    monkeypatch.setattr(enrichment_service.abuseipdb_client, "check_ip", fake_abuseipdb)
    monkeypatch.setattr(enrichment_service.otx_client, "check_ip", fake_otx)

    enrichment_service.enrich_ip(db_session, "118.25.6.39")
    enrichment_service.enrich_ip(db_session, "118.25.6.39")  # should hit cache

    assert calls["abuseipdb"] == 1  # NOT 2 — this is the whole point of the cache
    assert calls["otx"] == 1
    assert db_session.query(IOCEnrichment).count() == 1


def test_enrichment_summary_shape(db_session, monkeypatch):
    monkeypatch.setattr(
        enrichment_service.abuseipdb_client,
        "check_ip",
        lambda ip: {"abuseConfidenceScore": 90},
    )
    monkeypatch.setattr(
        enrichment_service.otx_client,
        "check_ip",
        lambda ip: {"pulse_info": {"count": 1}},
    )
    result = enrichment_service.enrich_ip(db_session, "118.25.6.39")
    summary = enrichment_service.enrichment_summary(result)
    assert summary["indicator"] == "118.25.6.39"
    assert "combined_threat_score" in summary
    assert "raw_abuseipdb" not in summary  # compact form, not the full raw blob


def test_enrichment_summary_none_for_none_input():
    assert enrichment_service.enrichment_summary(None) is None


def test_partial_failure_still_cached_within_short_cooldown(db_session, monkeypatch):
    """A failed source shouldn't be retried on every single call within the
    same burst — that would hammer an API that's already rate-limited,
    which is a likely cause of the failure in the first place. Within the
    short cooldown, the failed result is still served from cache."""
    calls = {"abuseipdb": 0}

    def fake_abuseipdb(ip):
        calls["abuseipdb"] += 1
        return None

    monkeypatch.setattr(enrichment_service.abuseipdb_client, "check_ip", fake_abuseipdb)
    monkeypatch.setattr(
        enrichment_service.otx_client,
        "check_ip",
        lambda ip: {"pulse_info": {"count": 0}},
    )

    enrichment_service.enrich_ip(db_session, "118.25.6.39")
    enrichment_service.enrich_ip(db_session, "118.25.6.39")  # immediately again

    assert calls["abuseipdb"] == 1  # NOT hammered a second time within the cooldown


def test_partial_failure_retried_after_cooldown_expires(db_session, monkeypatch):
    """Reproduces the exact bug found during Phase 5 verification: AbuseIPDB
    failed once (key issue, rate limit, etc.) while OTX succeeded with a
    genuine zero-pulse result. The old code cached that for the full 24h
    TTL — a transient failure looked identical to a clean IP for the rest
    of the day, even after the underlying issue was fixed. Confirms that
    once the (short) cooldown has actually elapsed, it retries for real."""
    calls = {"abuseipdb": 0}

    def fake_abuseipdb(ip):
        calls["abuseipdb"] += 1
        return None

    monkeypatch.setattr(enrichment_service.abuseipdb_client, "check_ip", fake_abuseipdb)
    monkeypatch.setattr(
        enrichment_service.otx_client,
        "check_ip",
        lambda ip: {"pulse_info": {"count": 0}},
    )

    first = enrichment_service.enrich_ip(db_session, "118.25.6.39")
    assert first.abuseipdb_score is None
    assert first.otx_pulse_count == 0  # OTX genuinely succeeded with a real answer

    # Simulate the cooldown having actually elapsed, rather than sleeping
    # 10 real minutes in a test.
    from datetime import datetime, timedelta, timezone

    first.fetched_at = datetime.now(timezone.utc) - timedelta(
        minutes=enrichment_service.FAILED_LOOKUP_RETRY_MINUTES + 1
    )
    db_session.commit()

    enrichment_service.enrich_ip(db_session, "118.25.6.39")
    assert calls["abuseipdb"] == 2  # cooldown expired — retried for real
