from app.detection.correlation import (
    aggregation_response_to_alerts,
    build_bruteforce_query,
)


def test_build_bruteforce_query_shape():
    query = build_bruteforce_query(lookback_minutes=10, threshold=5)
    agg = query["aggs"]["by_source_ip"]
    assert agg["terms"]["min_doc_count"] == 5
    assert query["size"] == 0  # aggregation-only, don't need the raw docs


def test_aggregation_response_produces_alert_per_bucket():
    fake_response = {
        "aggregations": {
            "by_source_ip": {
                "buckets": [
                    {
                        "key": "203.0.113.5",
                        "doc_count": 7,
                        "sample_event": {
                            "hits": {
                                "hits": [
                                    {
                                        "_source": {
                                            "message": "Failed password for admin from 203.0.113.5"
                                        }
                                    }
                                ]
                            }
                        },
                    }
                ]
            }
        }
    }
    alerts = aggregation_response_to_alerts(fake_response)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["detection_type"] == "correlation"
    assert alert["severity"] == "high"
    assert alert["mitre_techniques"] == ["T1110"]
    assert alert["source_event_id"].startswith("bruteforce:203.0.113.5:")
    assert alert["details"]["failed_count"] == 7


def test_no_buckets_produces_no_alerts():
    fake_response = {"aggregations": {"by_source_ip": {"buckets": []}}}
    assert aggregation_response_to_alerts(fake_response) == []
