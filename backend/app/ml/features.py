"""
Feature extraction for ML anomaly detection.

Eight features, all genuinely computable from what this pipeline already
indexes — no feature here depends on data the project doesn't actually
have. Computed by pulling matching documents client-side (capped at
MAX_EVENTS_PER_QUERY) rather than via server-side OpenSearch aggregations:
simpler to implement and test correctly, and sufficient at this project's
scale. A high-volume production version would push distinct_users,
distinct_hosts etc. into terms/cardinality aggregations instead, to avoid
transferring every matching document — a real trade-off, not an oversight.
"""

from datetime import datetime, timezone

from app.core.opensearch_client import INDEX_PATTERN, get_client

FEATURE_NAMES = [
    "total_events",
    "failed_login_count",
    "distinct_users",
    "distinct_hosts",
    "firewall_block_count",
    "distinct_source_types",
    "events_per_minute",
    "night_time_ratio",
]

MAX_EVENTS_PER_QUERY = 500


def _fetch_events_for_ip(source_ip: str, lookback_minutes: int) -> list[dict]:
    client = get_client()
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"source_ip": source_ip}},
                    {"range": {"event_timestamp": {"gte": f"now-{lookback_minutes}m"}}},
                ]
            }
        },
        "size": MAX_EVENTS_PER_QUERY,
    }
    response = client.search(index=INDEX_PATTERN, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def compute_features_from_events(events: list[dict], lookback_minutes: int) -> dict:
    """The pure, testable half — takes already-fetched event dicts (real
    OpenSearch _source docs or fakes shaped the same way) and computes the
    feature vector. Separated from _fetch_events_for_ip so this logic is
    testable without a live OpenSearch cluster."""
    total_events = len(events)
    if total_events == 0:
        return dict.fromkeys(FEATURE_NAMES, 0.0)

    failed_login_count = sum(
        1
        for e in events
        if e.get("source_type") == "linux_auth" and e.get("action") == "login_failed"
    )
    firewall_block_count = sum(
        1
        for e in events
        if e.get("source_type") == "firewall_json"
        and e.get("action") == "connection_block"
    )
    distinct_users = len({e["user"] for e in events if e.get("user")})
    distinct_hosts = len({e["host"] for e in events if e.get("host")})
    distinct_source_types = len(
        {e["source_type"] for e in events if e.get("source_type")}
    )

    night_events = 0
    for e in events:
        ts = e.get("event_timestamp")
        if not ts:
            continue
        try:
            hour = (
                datetime.fromisoformat(ts.replace("Z", "+00:00"))
                .astimezone(timezone.utc)
                .hour
            )
        except ValueError:
            continue
        if 0 <= hour < 6:
            night_events += 1
    night_time_ratio = night_events / total_events

    return {
        "total_events": float(total_events),
        "failed_login_count": float(failed_login_count),
        "distinct_users": float(distinct_users),
        "distinct_hosts": float(distinct_hosts),
        "firewall_block_count": float(firewall_block_count),
        "distinct_source_types": float(distinct_source_types),
        "events_per_minute": total_events / lookback_minutes,
        "night_time_ratio": night_time_ratio,
    }


def extract_features(source_ip: str, lookback_minutes: int = 60) -> dict:
    events = _fetch_events_for_ip(source_ip, lookback_minutes)
    return compute_features_from_events(events, lookback_minutes)


def get_recent_active_ips(lookback_minutes: int = 60, max_ips: int = 50) -> list[str]:
    """Distinct source_ips seen in the window — what /ml/score iterates
    over. A terms aggregation IS the right tool here (just need the
    distinct values, not the documents), unlike the per-IP feature
    extraction above."""
    client = get_client()
    query = {
        "query": {"range": {"event_timestamp": {"gte": f"now-{lookback_minutes}m"}}},
        "size": 0,
        "aggs": {"distinct_ips": {"terms": {"field": "source_ip", "size": max_ips}}},
    }
    response = client.search(index=INDEX_PATTERN, body=query)
    buckets = (
        response.get("aggregations", {}).get("distinct_ips", {}).get("buckets", [])
    )
    return [b["key"] for b in buckets]
