#!/bin/bash
# Tails this host's own auth.log and forwards each sshd line to Vantara's
# /ingest endpoint as a linux_auth event — the log-shipper piece the
# architecture doc's "Syslog" source assumes exists. Demo/dev-grade:
# no retry, no backpressure, no offset tracking across restarts.
#
# Usage: sudo ./backend/scripts/ship_auth_log.sh
set -euo pipefail
cd "$(dirname "$0")/../.."  # repo root
source .env

API_URL="http://localhost:8000/api/v1/ingest/events"

echo "Shipping new sshd auth events to ${API_URL} — Ctrl+C to stop."
tail -F -n0 /var/log/auth.log | grep --line-buffered "sshd\[" | while IFS= read -r line; do
  payload=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$line")
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL" \
    -H "X-API-Key: ${INGEST_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"source_type\": \"linux_auth\", \"payload\": ${payload}}")
  echo "[$code] $line"
done
