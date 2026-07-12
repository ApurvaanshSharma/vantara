# python:3.12-slim, not the full python:3.12 image — smaller image, faster
# pulls/builds. psycopg2-binary ships precompiled wheels, so no C compiler
# or libpq-dev needs installing here (that's only required for the
# non-binary `psycopg2` package, which we deliberately didn't choose).
FROM python:3.12-slim

WORKDIR /app

# Prevents Python from writing .pyc files and buffers stdout — both matter
# more in containers than on a host: unbuffered output means `docker compose
# logs` shows prints immediately instead of only on buffer flush/exit.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copied and installed before the rest of the source so Docker's layer cache
# only reinstalls dependencies when requirements.txt actually changes — not
# on every code edit.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# --reload is a local-dev convenience (auto-restarts on code changes via the
# bind mount in docker-compose.yml). A real deployment image would drop
# --reload and add --workers N — noting that now so it's a deliberate choice
# to revisit in Phase 18 (Deployment), not something forgotten.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
