"""
Centralized application settings.

Why this file exists: every other module that needs a config value (DB URL,
JWT secret, token lifetimes) imports `settings` from here instead of calling
os.environ.get() directly. That means:
  1. One place to see every environment variable the app depends on.
  2. Pydantic validates types and required-ness at startup, not at first use —
     a missing JWT_SECRET_KEY fails immediately on boot, not on the first
     login attempt three hours into a demo.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Populated from the DATABASE_URL environment variable (see docker-compose.yml).
    # Format: postgresql+psycopg2://<user>:<password>@<host>:<port>/<db>
    database_url: str

    # Signs and verifies JWTs. Must never be committed — comes from .env, which is gitignored.
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Redis Streams: the durable ingestion buffer. Same Redis instance also
    # backs Celery, but on a different logical DB (see celery_broker_url)
    # so the two don't collide in the same keyspace.
    redis_url: str = "redis://redis:6379/0"

    # OpenSearch: the sink for normalized events.
    opensearch_url: str = "http://opensearch:9200"

    # Shared-secret auth for log shippers hitting /ingest. Deliberately
    # separate from user JWTs — a syslog forwarder or Filebeat agent isn't
    # a human logging in, it's a long-lived credential a machine holds.
    ingest_api_key: str

    # Threat intel — both optional and empty by default. Enrichment is a
    # nice-to-have layered on top of detection, not a dependency of it;
    # the app must still start and detection must still work with neither
    # key configured. Free keys: abuseipdb.com/register,
    # otx.alienvault.com (Settings -> API Integration).
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""

    # Comma-separated, not a JSON list — matches how every other list-ish
    # value in this project's .env files gets written (simple, editable by
    # hand). "http://localhost:3000" covers the frontend's default port;
    # add the real origin here for anything beyond local dev.
    cors_origins: str = "http://localhost:3000"

    # SOAR notification webhook — optional, same graceful-degradation
    # contract as the threat intel keys: empty means the auto_case_notify
    # playbook still creates the case, just skips the notification step
    # rather than failing.
    webhook_url: str = ""

    @property
    def cors_origins_list(self) -> list[str]:
        return [
            origin.strip() for origin in self.cors_origins.split(",") if origin.strip()
        ]

    @property
    def celery_broker_url(self) -> str:
        # Same Redis host, DB index 1 instead of 0 — keeps Celery's internal
        # queue keys separate from our own Stream keys in DB 0.
        return self.redis_url.rsplit("/", 1)[0] + "/1"

    # SettingsConfigDict tells pydantic-settings where to look for a .env file
    # and that env var names are matched case-insensitively (DATABASE_URL -> database_url).
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"
    )


settings = Settings()
