#!/bin/bash
# Runs the backend test suite safely inside Docker, always against a
# dedicated vantara_test database — never the real 'vantara' database the
# rest of the stack uses. Written after a real incident: running
# `docker compose run --rm backend pytest` directly inherits the
# container's production DATABASE_URL, and the test suite's own fixtures
# truncate the alerts/ioc_enrichments tables as part of normal test
# isolation. Against production, that's data loss, not isolation.
#
# Usage: ./backend/scripts/run_tests_in_docker.sh [pytest args...]

set -euo pipefail
cd "$(dirname "$0")/../.."  # repo root, regardless of where this is invoked from

if [ ! -f .env ]; then
  echo "No .env found in repo root — run this from the project you set up in earlier phases."
  exit 1
fi

# shellcheck disable=SC1091
source .env

TEST_DB_URL="postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/vantara_test"

echo "Ensuring vantara_test database exists (safe to re-run — ignores 'already exists')..."
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -c "CREATE DATABASE vantara_test;" 2>&1 | grep -v "already exists" || true

echo "Applying migrations to vantara_test..."
docker compose run --rm -e DATABASE_URL="$TEST_DB_URL" backend alembic upgrade head

echo "Running tests against vantara_test..."
docker compose run --rm -e DATABASE_URL="$TEST_DB_URL" backend python -m pytest tests/ "$@"
