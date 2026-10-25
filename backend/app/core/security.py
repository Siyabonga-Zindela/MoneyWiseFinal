"""Password hashing, JWT minting and POPIA-safe hashing helpers."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from .config import settings


# --- passwords ---------------------------------------------------------------

def hash_password(plain: str) -> str:
    """bcrypt (cost from settings, default 12). users table CHECK enforces $2% prefix."""
    return bcrypt.hashpw(
        plain.encode("utf-8"), bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# --- one-way hashes (tokens at rest / POPIA IP hashing) -----------------------

def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_ip(ip: str) -> str:
    """Salted SHA-256 of a client IP. Raw IPs are never persisted (POPIA)."""
    return sha256_hex(f"{settings.ip_hash_salt}:{ip}")


# --- JWT ----------------------------------------------------------------------

def _create_token(
    subject: str, token_type: str, expires_delta: timedelta, extra: dict | None = None
) -> tuple[str, str]:
    jti = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "type": token_type,
        "jti": jti,
        "iat": now,
        "exp": now + expires_delta,
    }
    if extra:
        payload.update(extra)
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti


def create_access_token(user_id: int, roles: list[str]) -> str:
    token, _ = _create_token(
        str(user_id),
        "access",
        timedelta(minutes=settings.access_token_expire_minutes),
        {"roles": roles},
    )
    return token


def create_refresh_token(user_id: int) -> tuple[str, str, datetime]:
    """Returns (token, jti, expires_at). Only the SHA-256 hash is stored in the DB."""
    token, jti = _create_token(
        str(user_id), "refresh", timedelta(days=settings.refresh_token_expire_days)
    )
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )
    return token, jti, expires_at


def decode_token(token: str, expected_type: str) -> dict:
    """Decode + validate a JWT. Raises jwt.PyJWTError on any problem."""
    payload = jwt.decode(
        token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
    )
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"expected {expected_type} token")
    return payload
