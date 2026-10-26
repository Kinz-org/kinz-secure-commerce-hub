"""Application configuration loaded from environment variables.

Uses pydantic-settings BaseSettings for type coercion, validation, and
fail-fast behavior on missing/weak secrets in production.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# A list of secrets that are forbidden in production - if any of these
# are detected, the app refuses to start when NODE_ENV=production.
_INSECURE_SECRETS = frozenset(
    {
        "dev-only-change-me-in-production-please",
        "replace_with_at_least_32_random_bytes",
        "change_me_in_prod",
        "change-me-in-production-please",
        "",
    }
)

# Roles accepted by rbac.current_user. Kept here (not imported from rbac) because
# rbac -> jwt_handler -> config would be a circular import; a test asserts the
# two stay identical.
VALID_ROLES: tuple[str, ...] = ("viewer", "analyst", "admin")


class Settings(BaseSettings):
    """Strongly-typed settings loaded from environment (or .env)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- App ----
    APP_NAME: str = "KINZ Secure Commerce Hub"
    APP_VERSION: str = "1.0.0"
    NODE_ENV: str = "development"
    PORT_API: int = 8000

    # ---- Database ----
    DATABASE_URL: str = "postgresql+psycopg://kinz_app:change_me@localhost:5432/kinz_commerce"

    # ---- Security ----
    JWT_SECRET: str = "dev-only-change-me-in-production-please"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    JWT_ISSUER: str = "kinz-secure-commerce-hub"
    JWT_AUDIENCE: str = "kinz-api"
    BCRYPT_ROUNDS: int = 12
    RATE_LIMIT_PER_MINUTE: int = 120
    CORS_ORIGINS: str = "http://localhost:3000,https://kinz.vercel.app"

    # ---- Demo credentials (production: replace with DB-backed user store) ----
    # These are read from env so that the demo user's email/password hash
    # are NOT hardcoded in source. In production, set DEMO_USER_ENABLED=false
    # and use a real user store.
    DEMO_USER_ENABLED: bool = True
    DEMO_USER_EMAIL: str = "nassim@kinzoils.com"
    DEMO_USER_PASSWORD_HASH: str = ""
    DEMO_USER_ROLE: str = "admin"
    DEMO_USER_NAME: str = "Nassim K."

    # ---- Audit / logging ----
    AUDIT_LOG_PATH: str = "/tmp/kinz-audit.log"  # nosec B108 - dev default; overridden in prod
    AUDIT_LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB per file
    AUDIT_LOG_BACKUP_COUNT: int = 5
    LOG_LEVEL: str = "INFO"

    # ---- ETL ----
    ETL_CRON_SCHEDULE: str = "0 2 * * *"
    ETL_RAW_DIR: str = str(Path(__file__).resolve().parents[3] / "data" / "raw")
    ETL_PROCESSED_DIR: str = str(Path(__file__).resolve().parents[3] / "data" / "processed")

    # ---- Convenience ----
    @property
    def is_production(self) -> bool:
        return self.NODE_ENV.lower() in {"production", "prod"}

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # ---- Validators ----
    @field_validator("JWT_SECRET")
    @classmethod
    def _validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError(
                "JWT_SECRET must be at least 32 characters. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        return v

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def _validate_jwt_alg(cls, v: str) -> str:
        # Allow HS256/HS384/HS512 (symmetric) only. Disallow "none" explicitly.
        #
        # RS256/RS384/RS512 used to be accepted here, but jwt_handler signs and
        # verifies with JWT_SECRET - a shared string, not a PEM key pair - so an
        # RS* setting passed validation at startup and then made every login
        # fail at runtime (500 on /auth/login). Reject it up front instead;
        # asymmetric signing needs separate private/public key settings first.
        if v.lower() == "none":
            raise ValueError("JWT_ALGORITHM='none' is forbidden.")
        allowed = ("HS256", "HS384", "HS512")
        if v not in allowed:
            raise ValueError(
                f"JWT_ALGORITHM must be one of {', '.join(allowed)} (signing uses the shared "
                f"JWT_SECRET; asymmetric RS*/ES* keys are not supported); got {v!r}."
            )
        return v

    @field_validator("DEMO_USER_ROLE")
    @classmethod
    def _validate_demo_role(cls, v: str) -> str:
        # rbac.current_user rejects any token whose role is not one of these, so
        # a typo (e.g. "Admin") let the demo user log in and then get 401 on
        # every protected route. Fail at startup instead.
        if v not in VALID_ROLES:
            raise ValueError(
                f"DEMO_USER_ROLE must be one of {', '.join(VALID_ROLES)} (case-sensitive); got {v!r}."
            )
        return v

    def enforce_production_safety(self) -> None:
        """Hard-fail if production is started with insecure defaults.

        Called explicitly from main.py during lifespan startup so that
        misconfigured deploys crash immediately instead of running with
        a known secret.
        """
        if not self.is_production:
            return

        problems: list[str] = []
        if self.JWT_SECRET in _INSECURE_SECRETS:
            problems.append("JWT_SECRET is set to a known placeholder. Refusing to start in production.")
        # Reject known weak/default passwords in DATABASE_URL.
        # Parse the URL so we only check the password field, not the scheme
        # (which legitimately contains "postgresql" / "psycopg").
        weak_password_markers = ("change_me", "change-me", "password", "12345", "admin", "secret")
        try:
            from urllib.parse import urlparse

            parsed = urlparse(self.DATABASE_URL)
            db_password = parsed.password or ""
            if any(marker in db_password.lower() for marker in weak_password_markers):
                problems.append(
                    "DATABASE_URL password is weak or default. Refusing to start in production."
                )
        except Exception:
            # If we can't parse the URL, treat it as suspicious.
            problems.append("DATABASE_URL could not be parsed. Refusing to start in production.")
        if "*" in self.CORS_ORIGINS or "localhost" in self.CORS_ORIGINS:
            problems.append("CORS_ORIGINS contains a wildcard or localhost entry. Refusing to start in production.")
        if self.DEMO_USER_ENABLED:
            problems.append(
                "DEMO_USER_ENABLED=true in production. Set DEMO_USER_ENABLED=false and use a real user store."
            )
        if problems:
            joined = "\n  - ".join(problems)
            raise RuntimeError(f"Production safety checks failed:\n  - {joined}")

    @staticmethod
    def POSTGRES_PASSWORD_DEFAULT() -> str:
        """Used only by the production-safety check. Returns the placeholder."""
        return "change_me_in_prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
