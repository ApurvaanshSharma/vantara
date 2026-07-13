from app.detection.sigma_engine import (
    build_opensearch_query,
    hits_to_alert_dicts,
    load_sigma_rules,
    rule_mitre_techniques,
    translate_rule,
)


def test_loads_both_rule_files():
    rules = load_sigma_rules()
    titles = {r.title for r in rules}
    assert "SSH Authentication Failure" in titles
    assert "Firewall Connection Blocked" in titles


def test_ssh_rule_translates_to_expected_lucene_query():
    rule = next(
        r for r in load_sigma_rules() if r.title == "SSH Authentication Failure"
    )
    query = translate_rule(rule)
    assert "source_type:linux_auth" in query
    assert "action:login_failed" in query


def test_ssh_rule_mitre_technique_extracted():
    rule = next(
        r for r in load_sigma_rules() if r.title == "SSH Authentication Failure"
    )
    assert rule_mitre_techniques(rule) == ["T1110.001"]


def test_firewall_rule_has_no_mitre_technique():
    rule = next(
        r for r in load_sigma_rules() if r.title == "Firewall Connection Blocked"
    )
    assert rule_mitre_techniques(rule) == []


def test_build_opensearch_query_shape():
    query = build_opensearch_query("source_type:linux_auth", lookback_minutes=15)
    must_clauses = query["query"]["bool"]["must"]
    assert {"query_string": {"query": "source_type:linux_auth"}} in must_clauses
    assert any("range" in clause for clause in must_clauses)


def test_hits_to_alert_dicts_includes_mitre_technique_name_in_summary():
    rule = next(
        r for r in load_sigma_rules() if r.title == "SSH Authentication Failure"
    )
    fake_hits = [
        {
            "_id": "evt-123",
            "_source": {"message": "Failed password for admin from 203.0.113.5"},
        }
    ]
    alerts = hits_to_alert_dicts(rule, fake_hits)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["source_event_id"] == "evt-123"
    assert alert["detection_type"] == "sigma"
    assert alert["severity"] == "low"
    assert alert["mitre_techniques"] == ["T1110.001"]
    assert "Password Guessing" in alert["summary"]


def test_hits_to_alert_dicts_no_mitre_summary_when_rule_has_none():
    rule = next(
        r for r in load_sigma_rules() if r.title == "Firewall Connection Blocked"
    )
    fake_hits = [
        {"_id": "evt-456", "_source": {"message": "Firewall BLOCK 203.0.113.5"}}
    ]
    alerts = hits_to_alert_dicts(rule, fake_hits)
    assert alerts[0]["mitre_techniques"] == []
    assert "[" not in alerts[0]["summary"]  # no bracketed technique summary appended
