from app.core.config import settings

INGEST_HEADERS = {"X-API-Key": settings.ingest_api_key}


def test_ingest_rejects_missing_api_key(client):
    response = client.post(
        "/api/v1/ingest/events",
        json={"source_type": "generic_json", "payload": {"host": "x"}},
    )
    assert response.status_code == 401


def test_ingest_rejects_wrong_api_key(client):
    response = client.post(
        "/api/v1/ingest/events",
        json={"source_type": "generic_json", "payload": {"host": "x"}},
        headers={"X-API-Key": "wrong-key"},
    )
    assert response.status_code == 401


def test_ingest_generic_json_reaches_opensearch(client, mock_opensearch):
    response = client.post(
        "/api/v1/ingest/events",
        json={
            "source_type": "generic_json",
            "payload": {"host": "web01", "message": "hello"},
        },
        headers=INGEST_HEADERS,
    )
    assert response.status_code == 202

    # mock_opensearch is the indexed_docs list from conftest's fixture —
    # since Celery runs in eager mode, the task already ran synchronously
    # by the time this line executes, no polling/waiting needed.
    assert len(mock_opensearch) == 1
    assert mock_opensearch[0]["host"] == "web01"
    assert mock_opensearch[0]["message"] == "hello"
    assert mock_opensearch[0]["source_type"] == "generic_json"


def test_ingest_firewall_json_normalizes_correctly(client, mock_opensearch):
    client.post(
        "/api/v1/ingest/events",
        json={
            "source_type": "firewall_json",
            "payload": {
                "src_ip": "203.0.113.5",
                "dst_ip": "10.0.0.1",
                "action": "BLOCK",
            },
        },
        headers=INGEST_HEADERS,
    )
    assert len(mock_opensearch) == 1
    doc = mock_opensearch[0]
    assert doc["severity"] == "warning"
    assert doc["action"] == "connection_block"
    assert doc["source_ip"] == "203.0.113.5"


def test_ingest_linux_auth_normalizes_correctly(client, mock_opensearch):
    line = "Jul 12 10:23:45 webserver01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    client.post(
        "/api/v1/ingest/events",
        json={"source_type": "linux_auth", "payload": line},
        headers=INGEST_HEADERS,
    )
    assert len(mock_opensearch) == 1
    doc = mock_opensearch[0]
    assert doc["user"] == "admin"
    assert doc["action"] == "login_failed"
    assert doc["source_ip"] == "203.0.113.5"


def test_ingest_malformed_event_is_dropped_not_crashed(client, mock_opensearch):
    """A malformed event shouldn't reach OpenSearch, and shouldn't crash
    the batch — the response is still 202 because the event WAS durably
    queued; normalization failure happens downstream, asynchronously."""
    response = client.post(
        "/api/v1/ingest/events",
        json={"source_type": "linux_auth", "payload": "not a valid sshd line"},
        headers=INGEST_HEADERS,
    )
    assert response.status_code == 202
    assert len(mock_opensearch) == 0


def test_ingest_multiple_events_all_processed(client, mock_opensearch):
    for i in range(5):
        client.post(
            "/api/v1/ingest/events",
            json={"source_type": "generic_json", "payload": {"host": f"host{i}"}},
            headers=INGEST_HEADERS,
        )
    assert len(mock_opensearch) == 5
