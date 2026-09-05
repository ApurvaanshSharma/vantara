"""
FastAPI application entrypoint. Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload   (local dev)
or via the Dockerfile's CMD (no --reload in the container image).
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import auth, cases, detections, ingest, ml, soar, threat_intel
from app.core.config import settings
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

# Without this, every fetch() from the frontend (a different origin —
# localhost:3000 vs this API's localhost:8000, different ports count as
# different origins under CORS) gets silently blocked by the browser
# before the request even reaches FastAPI. Missing entirely until Phase 7
# added a real browser-based client — nothing before that exercised this
# path, since curl and pytest's TestClient don't enforce CORS at all.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(detections.router)
app.include_router(threat_intel.router)
app.include_router(ml.router)
app.include_router(cases.router)
app.include_router(soar.router)


@app.get("/health", tags=["health"])
def health() -> dict:
    """Used by Docker Compose / load balancers to check the API is up.
    Deliberately does NOT check the DB connection — that's a separate,
    deeper check (see /health/ready, added when the ingestion pipeline
    lands in Phase 3) so a slow DB doesn't get the whole API marked down."""
    return {"status": "ok"}
