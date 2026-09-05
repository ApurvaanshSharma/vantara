from app.models.alert import Alert, AlertSeverity, DetectionType
from app.soar.auto_tag import compute_tags


def _fake_alert(**overrides) -> Alert:
    defaults = dict(
        rule_id="test.rule",
        rule_title="Test Rule",
        detection_type=DetectionType.SIGMA,
        severity=AlertSeverity.HIGH,
        mitre_techniques=["T1110"],
        source_event_id="evt-1",
        summary="test",
        details={},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_tags_include_severity_and_source():
    alert = _fake_alert()
    tags = compute_tags(alert)
    assert "severity:high" in tags
    assert "source:sigma" in tags


def test_tags_include_mitre_techniques():
    alert = _fake_alert(mitre_techniques=["T1110", "T1059"])
    tags = compute_tags(alert)
    assert "mitre:T1110" in tags
    assert "mitre:T1059" in tags


def test_no_mitre_tags_when_alert_has_none():
    alert = _fake_alert(mitre_techniques=[])
    tags = compute_tags(alert)
    assert not any(t.startswith("mitre:") for t in tags)
