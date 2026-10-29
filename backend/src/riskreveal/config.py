"""Application configuration.

Settings are loaded from environment variables (and a local `.env` file in
development) via pydantic-settings. This module is intentionally strict:

- Secrets (``JWT_SECRET_KEY``, ``FERNET_KEY``) and the database URL have
  **no defaults**. If they are missing, the application fails to start
  with a clear error instead of silently falling back to an insecure
  built-in value. The original codebase shipped with hardcoded fallback
  secrets (including a Fernet key committed to the public repo) — this
  module exists specifically so that class of bug can't happen again.
- ``FERNET_KEY`` is validated as an actual usable Fernet key at startup,
  not just "a non-empty string", so a malformed key fails fast here
  rather than on the first credential-encryption call in production.
- Production-specific invariants (no debug mode, no wildcard CORS) are
  enforced centrally, once, rather than hoped for at each call site.

Usage::

    from riskreveal.config import get_settings

    settings = get_settings()
    engine = create_engine(settings.database_url)
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment. Drives the production-safety checks below."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Strongly-typed, validated application settings.

    Do not instantiate this directly in application code — call
    :func:`get_settings` instead, which caches a single validated
    instance for the lifetime of the process.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # Deliberately case-INsensitive (the default): environment variables
        # are conventionally UPPERCASE (DATABASE_URL) while Python fields
        # are lowercase (database_url). case_sensitive=True would require an
        # exact-case match and silently fail to pick up the standard
        # UPPERCASE env vars this file's own docstring and .env.example use.
        case_sensitive=False,
        extra="ignore",  # unrelated environment variables are not an error
    )

    # --- Core ------------------------------------------------------------
    app_name: str = "RiskReveal"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # --- Database ----------------------------------------------------------
    # Required — no default. A missing DATABASE_URL must stop the app from
    # starting, not silently fall back to sqlite or a local assumption.
    database_url: str = Field(
        ...,
        description="e.g. postgresql+psycopg://user:pass@localhost:5432/riskreveal",
    )

    # --- Redis (Celery broker/result backend, caching) --------------------
    # Lower risk than the secrets below (no credential material implied by
    # the default), so a sensible local default is acceptable here —
    # production deployments should still set this explicitly.
    redis_url: str = "redis://localhost:6379/0"

    # --- Secrets -----------------------------------------------------------
    # Required — no defaults, ever. See the module docstring.
    jwt_secret_key: SecretStr = Field(...)
    fernet_key: SecretStr = Field(...)

    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # --- CORS ----------------------------------------------------------------
    # NoDecode: by default pydantic-settings tries to JSON-decode any
    # list-typed field read from an environment variable, which would reject
    # a plain comma-separated value like "http://a.com,http://b.com" before
    # the _split_cors_origins validator below ever runs. NoDecode disables
    # that implicit JSON parsing so the raw string reaches the validator.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000"]
    )

    # --- Rate limiting -------------------------------------------------------
    auth_rate_limit: str = "5/minute"

    # --- Scanning scope policy -------------------------------------------
    # Whether scans are allowed to target private/loopback ranges at all.
    # Defaults closed; the scope-policy module (domain/scanning/scope_policy.py)
    # is what actually enforces this per-scan, this is just the global switch.
    scan_private_ranges_allowed: bool = False

    # --- AI agents -----------------------------------------------------------
    # Optional until the agent pipeline (Phase 5) is implemented — but
    # already typed correctly as a secret so it's never accidentally logged.
    anthropic_api_key: SecretStr | None = None

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, v: str) -> str:
        allowed_prefixes = ("postgresql://", "postgresql+psycopg://", "postgresql+asyncpg://")
        if not v.startswith(allowed_prefixes):
            raise ValueError(
                "DATABASE_URL must be a PostgreSQL connection string "
                f"starting with one of: {', '.join(allowed_prefixes)}"
            )
        return v

    @field_validator("redis_url")
    @classmethod
    def _validate_redis_url(cls, v: str) -> str:
        if not v.startswith(("redis://", "rediss://")):
            raise ValueError("REDIS_URL must start with redis:// or rediss://")
        return v

    @field_validator("jwt_secret_key")
    @classmethod
    def _validate_jwt_secret_length(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError(
                "JWT_SECRET_KEY must be at least 32 characters. Generate one with:\n"
                '  python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        return v

    @field_validator("fernet_key")
    @classmethod
    def _validate_fernet_key(cls, v: SecretStr) -> SecretStr:
        try:
            Fernet(v.get_secret_value().encode("utf-8"))
        except Exception as exc:
            # Intentionally broad: Fernet() raises different exception types
            # (binascii.Error, ValueError) depending on *how* the key is
            # malformed, and the only correct response to any of them is
            # "reject this key with a clear message" — not which subtype hit.
            raise ValueError(
                "FERNET_KEY must be a valid 32-byte urlsafe-base64-encoded Fernet key. "
                "Generate one with:\n"
                '  python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            ) from exc
        return v

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors_origins(cls, v: object) -> object:
        # Environment variables arrive as strings; allow a comma-separated
        # list in .env (CORS_ORIGINS=http://a,http://b) while still
        # accepting an actual list when constructed programmatically (tests).
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def _enforce_production_safety(self) -> Settings:
        if self.environment is Environment.PRODUCTION:
            if self.debug:
                raise ValueError("DEBUG must be false when ENVIRONMENT=production.")
            if "*" in self.cors_origins:
                raise ValueError("CORS_ORIGINS must not contain '*' when ENVIRONMENT=production.")
        return self

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.environment is Environment.DEVELOPMENT


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings` instance.

    Cached with ``lru_cache`` so settings are parsed and validated exactly
    once per process, and so every module that needs config gets the same
    instance (and therefore the same validation guarantees) rather than
    re-reading and re-validating the environment on every call.
    """

    # Required fields have no Python-level defaults by design (see module
    # docstring) but are supplied at runtime via environment variables or
    # the .env file, which pydantic-settings' pydantic.mypy plugin already
    # accounts for — no type: ignore needed here.
    return Settings()