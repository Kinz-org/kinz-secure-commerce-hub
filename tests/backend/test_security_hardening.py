"""Tests for the production-readiness security hardening.

Covers:
  - JWT now requires iss / aud / jti claims (rejects legacy tokens)
  - JWT_SECRET validator rejects short / placeholder secrets
  - Production safety check fails on insecure defaults
  - Demo user login flow works with real bcrypt hash from env
  - Demo user login fails when DEMO_USER_ENABLED=false
  - Audit logger rotates when the file exceeds max_bytes
"""
from __future__ import annotations

import importlib
import os

import jwt
import pytest

# ────────────────────────────────────────────────────────────
# 1. JWT claims - iss / aud / jti are now required
# ────────────────────────────────────────────────────────────


def test_jwt_includes_iss_aud_jti_claims():
    from src.api.security.jwt_handler import issue_token, verify_token

    token = issue_token(subject="user@example.com", role="viewer")
    claims = verify_token(token)
    assert claims["iss"] == os.environ["JWT_ISSUER"]
    assert claims["aud"] == os.environ["JWT_AUDIENCE"]
    assert "jti" in claims
    # jti must be a non-empty string (UUID4)
    assert isinstance(claims["jti"], str) and len(claims["jti"]) > 0


def test_jwt_rejects_token_missing_iss():
    """A token without iss must be rejected (defense against cross-service reuse)."""
    from src.api.utils.config import settings

    payload = {
        "sub": "x@y.z",
        "role": "viewer",
        "iat": 1_700_000_000,
        "exp": 9_999_999_999,
        "aud": settings.JWT_AUDIENCE,
        "jti": "abc",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.MissingRequiredClaimError):
        from src.api.security.jwt_handler import verify_token

        verify_token(token)


def test_jwt_rejects_token_missing_aud():
    from src.api.utils.config import settings

    payload = {
        "sub": "x@y.z",
        "role": "viewer",
        "iat": 1_700_000_000,
        "exp": 9_999_999_999,
        "iss": settings.JWT_ISSUER,
        "jti": "abc",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.MissingRequiredClaimError):
        from src.api.security.jwt_handler import verify_token

        verify_token(token)


def test_jwt_rejects_token_with_wrong_issuer():
    """Tokens issued by a different service must be rejected."""
    from src.api.utils.config import settings

    payload = {
        "sub": "x@y.z",
        "role": "viewer",
        "iat": 1_700_000_000,
        "exp": 9_999_999_999,
        "iss": "evil-other-service",
        "aud": settings.JWT_AUDIENCE,
        "jti": "abc",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.InvalidIssuerError):
        from src.api.security.jwt_handler import verify_token

        verify_token(token)


def test_jwt_rejects_token_with_wrong_audience():
    from src.api.utils.config import settings

    payload = {
        "sub": "x@y.z",
        "role": "viewer",
        "iat": 1_700_000_000,
        "exp": 9_999_999_999,
        "iss": settings.JWT_ISSUER,
        "aud": "wrong-audience",
        "jti": "abc",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.InvalidAudienceError):
        from src.api.security.jwt_handler import verify_token

        verify_token(token)


# ────────────────────────────────────────────────────────────
# 2. JWT_SECRET validation
# ────────────────────────────────────────────────────────────


def test_jwt_secret_too_short_raises():
    """A secret < 32 chars must raise on Settings instantiation."""
    from src.api.utils.config import Settings

    with pytest.raises(Exception) as exc_info:
        Settings(JWT_SECRET="short")
    assert "32" in str(exc_info.value)


def test_jwt_secret_none_algorithm_forbidden():
    from src.api.utils.config import Settings

    with pytest.raises(Exception):
        Settings(JWT_ALGORITHM="none")


@pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
def test_jwt_asymmetric_algorithm_rejected_at_startup(alg):
    """RS* used to pass validation, but tokens are signed with the shared
    JWT_SECRET string, so signing then failed on every login. It must be
    refused when settings load, not at the first request."""
    from src.api.utils.config import Settings

    with pytest.raises(Exception) as exc_info:
        Settings(JWT_ALGORITHM=alg)
    assert "JWT_ALGORITHM" in str(exc_info.value)


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_jwt_symmetric_algorithms_round_trip(alg):
    """Every algorithm the validator accepts must actually sign and verify
    with JWT_SECRET - the invariant the RS* entries broke."""
    from src.api.utils.config import Settings

    s = Settings(JWT_ALGORITHM=alg)
    claims = {"sub": "x@y.z", "role": "viewer"}
    token = jwt.encode(claims, s.JWT_SECRET, algorithm=s.JWT_ALGORITHM)
    assert jwt.decode(token, s.JWT_SECRET, algorithms=[s.JWT_ALGORITHM]) == claims


# ────────────────────────────────────────────────────────────
# 3. Production safety check
# ────────────────────────────────────────────────────────────


def _reload_settings_with(**env):
    """Reload the settings module with the given env vars set."""
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    import src.api.utils.config as cfg

    importlib.reload(cfg)
    return cfg


def test_production_safety_rejects_default_jwt_secret(monkeypatch):
    """In production, JWT_SECRET=placeholder must raise."""
    from src.api.utils.config import Settings

    s = Settings(
        NODE_ENV="production",
        JWT_SECRET="dev-only-change-me-in-production-please",
        DATABASE_URL="postgresql+psycopg://u:strongpass@db:5432/app",
        CORS_ORIGINS="https://kinz.vercel.app",
        DEMO_USER_ENABLED=False,
    )
    with pytest.raises(RuntimeError) as exc_info:
        s.enforce_production_safety()
    assert "JWT_SECRET" in str(exc_info.value)


def test_production_safety_rejects_wildcard_cors(monkeypatch):
    from src.api.utils.config import Settings

    s = Settings(
        NODE_ENV="production",
        JWT_SECRET="a" * 48,  # strong secret
        DATABASE_URL="postgresql+psycopg://u:strongpass@db:5432/app",
        CORS_ORIGINS="*",  # wildcard - forbidden in prod
        DEMO_USER_ENABLED=False,
    )
    with pytest.raises(RuntimeError) as exc_info:
        s.enforce_production_safety()
    assert "CORS_ORIGINS" in str(exc_info.value)


def test_production_safety_rejects_demo_user_in_prod():
    from src.api.utils.config import Settings

    s = Settings(
        NODE_ENV="production",
        JWT_SECRET="a" * 48,
        DATABASE_URL="postgresql+psycopg://u:strongpass@db:5432/app",
        CORS_ORIGINS="https://kinz.vercel.app",
        DEMO_USER_ENABLED=True,
    )
    with pytest.raises(RuntimeError) as exc_info:
        s.enforce_production_safety()
    assert "DEMO_USER_ENABLED" in str(exc_info.value)


def test_production_safety_passes_with_secure_config():
    from src.api.utils.config import Settings

    s = Settings(
        NODE_ENV="production",
        JWT_SECRET="a" * 48,
        DATABASE_URL="postgresql+psycopg://u:strongpass@db:5432/app",
        CORS_ORIGINS="https://kinz.vercel.app",
        DEMO_USER_ENABLED=False,
    )
    # Should not raise
    s.enforce_production_safety()


# ────────────────────────────────────────────────────────────
# 4. Demo user login flow
# ────────────────────────────────────────────────────────────


def test_demo_login_succeeds_with_real_bcrypt_hash(client):
    """The demo user can actually log in (was previously broken by an
    invalid bcrypt hash placeholder)."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "nassim@kinzoils.com", "password": "KINZ-demo-2025!"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] == 3600  # 60 min


def test_demo_login_rejects_wrong_password(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "nassim@kinzoils.com", "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


def test_demo_login_rejects_invalid_email_format(client):
    """LoginRequest.email is now EmailStr - must reject malformed emails."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "not-an-email", "password": "KINZ-demo-2025!"},
    )
    assert resp.status_code == 422  # Unprocessable Entity (pydantic validation)


def test_me_endpoint_returns_full_claims(client):
    """The /me endpoint now exposes iss / aud / jti for debugging."""
    from src.api.security.jwt_handler import issue_token

    token = issue_token(subject="nassim@kinzoils.com", role="admin")
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "nassim@kinzoils.com"
    assert body["role"] == "admin"
    assert body["issuer"]  # iss
    assert body["audience"]  # aud
    assert body["jti"]  # jti


# ────────────────────────────────────────────────────────────
# 5. Audit log rotation
# ────────────────────────────────────────────────────────────


def test_audit_logger_rotates_when_max_bytes_exceeded(tmp_path):
    from src.api.security.audit import AuditLogger

    log_path = tmp_path / "audit.log"
    # Tiny limit so a single event triggers rotation
    logger = AuditLogger(path=str(log_path), max_bytes=120, backup_count=3)

    # Write enough events to force at least one rotation
    for i in range(20):
        logger.log("test.event", user="tester", detail=f"iteration-{i:02d}")

    # The primary file must exist, plus at least one rotated backup
    assert log_path.exists()
    rotated = list(tmp_path.glob("audit.log.*"))
    assert len(rotated) >= 1, f"Expected at least 1 rotated backup, got {rotated}"


def test_audit_logger_creates_file_with_0600_permissions(tmp_path):
    from src.api.security.audit import AuditLogger

    log_path = tmp_path / "audit.log"
    AuditLogger(path=str(log_path))
    mode = log_path.stat().st_mode & 0o777
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


# ────────────────────────────────────────────────────────────
# 6. OWASP headers - verify the new CORP/COEP/COOP trio
# ────────────────────────────────────────────────────────────


def test_response_includes_corp_coep_coop_headers(client):
    resp = client.get("/health")
    assert resp.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
    assert resp.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
    assert resp.headers.get("Cross-Origin-Embedder-Policy") == "require-corp"
    assert resp.headers.get("X-DNS-Prefetch-Control") == "off"


def test_api_responses_have_no_store_cache_control(client):
    from src.api.security.jwt_handler import issue_token

    token = issue_token(subject="nassim@kinzoils.com", role="admin")
    resp = client.get("/api/v1/products", headers={"Authorization": f"Bearer {token}"})
    cache = resp.headers.get("Cache-Control", "")
    assert "no-store" in cache
    assert "no-cache" in cache


def test_response_includes_request_id_header(client):
    """Every response must echo back an X-Request-ID."""
    resp = client.get("/health")
    assert "X-Request-ID" in resp.headers
    assert len(resp.headers["X-Request-ID"]) > 0


def test_response_echoes_client_request_id(client):
    """If the client sends X-Request-ID, the server must echo the same value."""
    custom_id = "my-trace-id-12345"
    resp = client.get("/health", headers={"X-Request-ID": custom_id})
    assert resp.headers["X-Request-ID"] == custom_id
