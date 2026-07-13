"""
Sigma detection engine.

Deliberately split into small pure functions (load / translate / build
query / parse hits) rather than one big function — each piece is testable
without needing a live OpenSearch cluster except the one that actually
calls it. Only `run_sigma_detection`'s call to `client.search()` needs a
mock in tests; everything else is real logic under real test.

Runs on a lookback window (not "since last run") deliberately: if this
sweep is triggered irregularly (see api/routes/detections.py), a fixed
lookback with overlap is simpler and safer than tracking last-run state —
the Alert table's unique constraint absorbs the resulting duplicate
matches for free.
"""

import glob
import os

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection

from app.core.opensearch_client import INDEX_PATTERN, get_client
from app.detection.mitre import technique_name

_RULES_DIR = os.path.join(os.path.dirname(__file__), "sigma_rules")


def load_sigma_rules() -> list:
    rules = []
    for path in sorted(glob.glob(os.path.join(_RULES_DIR, "*.yml"))):
        with open(path) as f:
            collection = SigmaCollection.from_yaml(f.read())
        rules.extend(collection.rules)
    return rules


def translate_rule(rule) -> str:
    backend = LuceneBackend()
    return backend.convert(SigmaCollection([rule]))[0]


def rule_mitre_techniques(rule) -> list[str]:
    return [
        tag.name.upper()
        for tag in rule.tags
        if tag.namespace == "attack" and tag.name[0] == "t"
    ]


def build_opensearch_query(lucene_query: str, lookback_minutes: int) -> dict:
    return {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": lucene_query}},
                    {"range": {"event_timestamp": {"gte": f"now-{lookback_minutes}m"}}},
                ]
            }
        },
        "size": 200,
    }


def hits_to_alert_dicts(rule, hits: list[dict]) -> list[dict]:
    mitre = rule_mitre_techniques(rule)
    technique_summary = ", ".join(technique_name(t) for t in mitre) if mitre else None

    alerts = []
    for hit in hits:
        source = hit["_source"]
        summary = f"{rule.title}: {source.get('message', '(no message)')}"
        if technique_summary:
            summary = f"{summary} [{technique_summary}]"
        alerts.append(
            {
                "rule_id": str(rule.id),
                "rule_title": rule.title,
                "detection_type": "sigma",
                "severity": str(rule.level),
                "mitre_techniques": mitre,
                "source_event_id": hit["_id"],
                "summary": summary,
                "details": {"matched_event": source},
            }
        )
    return alerts


def run_sigma_detection(lookback_minutes: int = 20) -> list[dict]:
    client = get_client()
    all_alerts = []
    for rule in load_sigma_rules():
        lucene_query = translate_rule(rule)
        query = build_opensearch_query(lucene_query, lookback_minutes)
        response = client.search(index=INDEX_PATTERN, body=query)
        hits = response["hits"]["hits"]
        all_alerts.extend(hits_to_alert_dicts(rule, hits))
    return all_alerts
