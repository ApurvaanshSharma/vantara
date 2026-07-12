"""
FastAPI application entrypoint. Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload   (local dev)
or via the Dockerfile's CMD (no --reload in the container image).
"""

from fastapi import FastAPI

from app.api.routes import auth

app = FastAPI(
    title="Vantara API",
    description="AI-native SOC platform — backend API",
    version="0.1.0",
)

app.include_router(auth.router)


@app.get("/health", tags=["health"])
def health() -> dict:
    """Used by Docker Compose / load balancers to check the API is up.
    Deliberately does NOT check the DB connection — that's a separate,
    deeper check (see /health/ready, added when the ingestion pipeline
    lands in Phase 3) so a slow DB doesn't get the whole API marked down."""
    return {"status": "ok"}
