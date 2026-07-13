"""
Brute-force correlation — deliberately NOT a Sigma rule.

Classic Sigma rules (what pySigma + this project's backend translate)
match single events. "5+ failed logins from the same IP in 10 minutes" is
a statement about *counts over a time window*, which needs the newer Sigma
Correlation spec (2023+) or a purpose-built aggregation query. This project
uses a purpose-built aggregation deliberately — it's the more transparent
choice for a learning project than pulling in Sigma Correlation support
for exactly one rule.

Window bucketing (by hour) is the dedup mechanism: an IP that's still over
threshold in the same hour on a later sweep doesn't produce a second
alert; a genuinely new burst starting in the next hour does. A production
correlation engine would use a sliding window with explicit suppression
windows — this is the deliberately simpler version of the same idea.
"""

from datetime import datetime, timezone

from app.core.opensearch_client import INDEX_PATTERN, get_client
from app.detection.mitre import technique_name

RULE_ID = "correlation.ssh_bruteforce"
RULE_TITLE = "SSH Brute Force (Correlated)"
MITRE_TECHNIQUES = ["T1110"]
THRESHOLD = 5


def build_bruteforce_query(lookback_minutes: int, threshold: int) -> dict:
    return {
        "query": {
            "bool": {
                "must": [
                    {"term": {"source_type": "linux_auth"}},
                    {"term": {"action": "login_failed"}},
                    {"range": {"event_timestamp": {"gte": f"now-{lookback_minutes}m"}}},
                ]
            }
        },
        "size": 0,
        "aggs": {
            "by_source_ip": {
                "terms": {"field": "source_ip", "min_doc_count": threshold},
                "aggs": {"sample_event": {"top_hits": {"size": 1}}},
            }
        },
    }


def aggregation_response_to_alerts(response: dict) -> list[dict]:
    buckets = (
        response.get("aggregations", {}).get("by_source_ip", {}).get("buckets", [])
    )
    hour_bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    technique_summary = ", ".join(technique_name(t) for t in MITRE_TECHNIQUES)

    alerts = []
    for bucket in buckets:
        source_ip = bucket["key"]
        count = bucket["doc_count"]
        sample_hit = bucket["sample_event"]["hits"]["hits"][0]
        alerts.append(
            {
                "rule_id": RULE_ID,
                "rule_title": RULE_TITLE,
                "detection_type": "correlation",
                "severity": "high",
                "mitre_techniques": MITRE_TECHNIQUES,
                "source_event_id": f"bruteforce:{source_ip}:{hour_bucket}",
                "summary": (
                    f"{count} failed SSH logins from {source_ip} in the last window "
                    f"[{technique_summary}]"
                ),
                "details": {
                    "source_ip": source_ip,
                    "failed_count": count,
                    "sample_event": sample_hit["_source"],
                },
            }
        )
    return alerts


def run_bruteforce_detection(
    lookback_minutes: int = 20, threshold: int = THRESHOLD
) -> list[dict]:
    client = get_client()
    query = build_bruteforce_query(lookback_minutes, threshold)
    response = client.search(index=INDEX_PATTERN, body=query)
    return aggregation_response_to_alerts(response)
