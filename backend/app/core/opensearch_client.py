"""
OpenSearch client, index template, and indexing.

Events land in a daily index (vantara-events-YYYY.MM.DD) matching the
index template below — a standard SIEM pattern: old daily indices can be
deleted/archived independently as a retention policy, without touching
today's writes. Index Lifecycle Management (automating that rollover and
deletion) is real, and deliberately out of scope here — this just creates
the pattern ILM would later manage.
"""

from datetime import datetime, timezone

from opensearchpy import OpenSearch

from app.core.config import settings

INDEX_TEMPLATE_NAME = "vantara-events-template"
INDEX_PATTERN = "vantara-events-*"

_INDEX_TEMPLATE_BODY = {
    "index_patterns": [INDEX_PATTERN],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "event_id": {"type": "keyword"},
                "ingested_at": {"type": "date"},
                "event_timestamp": {"type": "date"},
                "source_type": {"type": "keyword"},
                "host": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "action": {"type": "keyword"},
                "user": {"type": "keyword"},
                # "ip" type (not keyword) enables CIDR-range queries later —
                # e.g. "all events from 203.0.113.0/24" — that a keyword
                # field can only match as an exact string.
                "source_ip": {"type": "ip"},
                "destination_ip": {"type": "ip"},
                "message": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "raw": {
                    "type": "object",
                    "enabled": False,
                },  # stored, not indexed/searchable
            }
        },
    },
}


def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[settings.opensearch_url], use_ssl=False, verify_certs=False
    )


def ensure_index_template(client: OpenSearch | None = None) -> None:
    client = client or get_client()
    client.indices.put_index_template(
        name=INDEX_TEMPLATE_NAME, body=_INDEX_TEMPLATE_BODY
    )


def current_index_name() -> str:
    return f"vantara-events-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


def index_event(doc: dict, client: OpenSearch | None = None) -> None:
    client = client or get_client()
    client.index(index=current_index_name(), body=doc, id=doc["event_id"])
