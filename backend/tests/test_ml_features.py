from app.ml.features import FEATURE_NAMES, compute_features_from_events


def test_empty_events_gives_zero_vector():
    result = compute_features_from_events([], lookback_minutes=60)
    assert all(result[name] == 0.0 for name in FEATURE_NAMES)


def test_counts_failed_logins_and_distinct_users():
    events = [
        {
            "source_type": "linux_auth",
            "action": "login_failed",
            "user": "admin",
            "host": "web01",
            "event_timestamp": "2026-07-13T12:00:00Z",
        },
        {
            "source_type": "linux_auth",
            "action": "login_failed",
            "user": "root",
            "host": "web01",
            "event_timestamp": "2026-07-13T12:01:00Z",
        },
        {
            "source_type": "linux_auth",
            "action": "login_succeeded",
            "user": "deploy",
            "host": "web02",
            "event_timestamp": "2026-07-13T12:02:00Z",
        },
    ]
    result = compute_features_from_events(events, lookback_minutes=10)
    assert result["total_events"] == 3
    assert result["failed_login_count"] == 2
    assert result["distinct_users"] == 3  # admin, root, deploy
    assert result["distinct_hosts"] == 2  # web01, web02
    assert result["distinct_source_types"] == 1


def test_events_per_minute_uses_lookback_window():
    events = [
        {"source_type": "generic_json", "event_timestamp": "2026-07-13T12:00:00Z"}
    ] * 30
    result = compute_features_from_events(events, lookback_minutes=15)
    assert result["events_per_minute"] == 2.0


def test_night_time_ratio_computed_correctly():
    events = [
        {
            "source_type": "generic_json",
            "event_timestamp": "2026-07-13T02:00:00Z",
        },  # night
        {
            "source_type": "generic_json",
            "event_timestamp": "2026-07-13T03:00:00Z",
        },  # night
        {
            "source_type": "generic_json",
            "event_timestamp": "2026-07-13T14:00:00Z",
        },  # day
        {
            "source_type": "generic_json",
            "event_timestamp": "2026-07-13T15:00:00Z",
        },  # day
    ]
    result = compute_features_from_events(events, lookback_minutes=60)
    assert result["night_time_ratio"] == 0.5


def test_firewall_block_count():
    events = [
        {"source_type": "firewall_json", "action": "connection_block"},
        {"source_type": "firewall_json", "action": "connection_block"},
        {"source_type": "firewall_json", "action": "connection_allow"},
    ]
    result = compute_features_from_events(events, lookback_minutes=10)
    assert result["firewall_block_count"] == 2
