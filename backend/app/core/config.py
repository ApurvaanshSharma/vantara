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

    # SettingsConfigDict tells pydantic-settings where to look for a .env file
    # and that env var names are matched case-insensitively (DATABASE_URL -> database_url).
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"
    )


settings = Settings()
