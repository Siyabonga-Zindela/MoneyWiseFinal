"""Application configuration (loaded from environment / backend/.env)."""

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- application ---------------------------------------------------------
    app_name: str = "MoneyWise API"
    environment: str = "development"

    # --- database (Neon PostgreSQL) ------------------------------------------
    database_url: str = "postgresql://postgres:postgres@localhost:5432/moneywise"

    # --- auth / JWT -----------------------------------------------------------
    jwt_secret_key: str = "dev-only-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    bcrypt_rounds: int = 12

    # --- brute-force protection (backed by login_attempts table) --------------
    failed_login_window_minutes: int = 15
    failed_login_max_attempts: int = 5
    account_lock_minutes: int = 15
    rate_limit_auth: str = "5/minute"

    # --- public report uploads (anonymous, multipart) --------------------------
    rate_limit_reports: str = "10/minute"

    # --- request size guard (screenshots cap at 5 MB; 8 MB covers the rest) ---
    max_body_mb: int = 8

    # --- POPIA: raw IPs are never stored, only salted hashes -------------------
    ip_hash_salt: str = "dev-only-change-salt"

    # --- CORS (vanilla JS frontend) --------------------------------------------
    cors_origins: str = (
        "http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000"
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @field_validator("database_url")
    @classmethod
    def _normalise_driver(cls, value: str) -> str:
        """Ship psycopg2-binary: make bare postgres:// URLs explicit so SQLAlchemy
        does not look for psycopg3 (not installed)."""
        if value.startswith("postgres://"):
            value = value.replace("postgres://", "postgresql://", 1)
        if value.startswith("postgresql://"):
            value = value.replace("postgresql://", "postgresql+psycopg2://", 1)
        return value

    @field_validator("jwt_secret_key", "ip_hash_salt")
    @classmethod
    def _reject_placeholder_in_production(cls, value: str, info):
        if info.data.get("environment") == "production" and "change" in value.lower():
            raise ValueError(
                f"{info.field_name} is still a placeholder - refusing to run in production"
            )
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
