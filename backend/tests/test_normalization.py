import pytest

from app.core.normalization import (
    NormalizationError,
    normalize_firewall_json,
    normalize_generic_json,
    normalize_linux_auth,
)


def test_generic_json_passthrough():
    event = normalize_generic_json({"host": "web01", "message": "custom app event"})
    assert event.source_type == "generic_json"
    assert event.host == "web01"
    assert event.message == "custom app event"


def test_generic_json_missing_message_gets_placeholder():
    event = normalize_generic_json({"host": "web01"})
    assert "no message" in event.message


def test_firewall_json_block_is_warning_severity():
    event = normalize_firewall_json(
        {"src_ip": "203.0.113.5", "dst_ip": "10.0.0.1", "action": "BLOCK"}
    )
    assert event.severity == "warning"
    assert event.action == "connection_block"
    assert event.source_ip == "203.0.113.5"
    assert event.destination_ip == "10.0.0.1"


def test_firewall_json_allow_is_info_severity():
    event = normalize_firewall_json({"src_ip": "203.0.113.5", "action": "ALLOW"})
    assert event.severity == "info"


def test_firewall_json_missing_required_field_raises():
    with pytest.raises(NormalizationError):
        normalize_firewall_json({"action": "BLOCK"})  # missing src_ip


def test_linux_auth_failed_password_parses_correctly():
    line = "Jul 12 10:23:45 webserver01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    event = normalize_linux_auth(line)
    assert event.host == "webserver01"
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.5"
    assert event.action == "login_failed"
    assert event.severity == "warning"


def test_linux_auth_accepted_password_parses_correctly():
    line = "Jul 12 10:23:45 webserver01 sshd[1234]: Accepted password for deploy from 203.0.113.7 port 51520 ssh2"
    event = normalize_linux_auth(line)
    assert event.user == "deploy"
    assert event.action == "login_succeeded"
    assert event.severity == "info"


def test_linux_auth_unrecognized_line_raises():
    with pytest.raises(NormalizationError):
        normalize_linux_auth("this is not an sshd log line at all")
