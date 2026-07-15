"""
FastAPI application entrypoint. Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload   (local dev)
or via the Dockerfile's CMD (no --reload in the container image).
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import auth, detections, ingest, threat_intel
from app.core.opensearch_client import ensure_index_template
from app.core.redis_client import ensure_consumer_group


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Idempotent — safe to run on every restart, not just the first boot.
    ensure_consumer_group()
    ensure_index_template()
    yield


app = FastAPI(
    title="Vantara API",
    description="AI-native SOC platform — backend API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(detections.router)
app.include_router(threat_intel.router)


@app.get("/health", tags=["health"])
def health() -> dict:
    """Used by Docker Compose / load balancers to check the API is up.
    Deliberately does NOT check the DB connection — that's a separate,
    deeper check (see /health/ready, added when the ingestion pipeline
    lands in Phase 3) so a slow DB doesn't get the whole API marked down."""
    return {"status": "ok"}
