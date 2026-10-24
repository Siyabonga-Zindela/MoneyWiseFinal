"""Unit tests for password hashing and JWT helpers (no DB needed)."""

import jwt as pyjwt
import pytest

from backend.app.core import security


def test_password_hash_roundtrip():
    hashed = security.hash_password("Str0ngPassw0rd!")
    assert hashed.startswith("$2b$12$")
    assert security.verify_password("Str0ngPassw0rd!", hashed)
    assert not security.verify_password("wrong-password", hashed)


def test_access_token_roundtrip():
    token = security.create_access_token(42, ["USER", "ADMIN"])
    payload = security.decode_token(token, expected_type="access")
    assert payload["sub"] == "42"
    assert payload["roles"] == ["USER", "ADMIN"]
    assert payload["type"] == "access"
    assert payload["jti"]


def test_refresh_token_rejected_as_access():
    token, _jti, _exp = security.create_refresh_token(42)
    with pytest.raises(pyjwt.InvalidTokenError):
        security.decode_token(token, expected_type="access")


def test_tampered_token_rejected():
    token = security.create_access_token(1, [])
    with pytest.raises(pyjwt.PyJWTError):
        security.decode_token(token + "x", expected_type="access")


def test_ip_hash_is_salted_and_stable():
    assert security.hash_ip("1.2.3.4") == security.hash_ip("1.2.3.4")
    # Salted: must NOT equal a plain SHA-256 of the IP.
    assert security.hash_ip("1.2.3.4") != security.sha256_hex("1.2.3.4")
