"""Unit tests for password hashing and JWT helpers, plus integration tests
for the platform security controls (headers, body limit, input validation).
Integration tests use the shared TestClient fixture (see conftest.py)."""

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


# --- platform controls (integration) -----------------------------------------


def test_security_headers_on_every_response(client):
    for path in ("/health", "/", "/check.html"):
        resp = client.get(path)
        assert resp.status_code in (200, 503), path  # 503 only if DB degraded
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "script-src 'self'" in csp  # no inline script allowed
        assert "frame-ancestors 'none'" in csp


def test_health_does_not_leak_environment_details(client):
    resp = client.get("/health")
    body = resp.json()
    assert "environment" not in body
    assert "version" not in body


def test_static_pages_served_from_app_root(client):
    index = client.get("/")
    assert index.status_code == 200
    assert "Spot the scam" in index.text          # landing page hero
    check = client.get("/check.html")
    assert check.status_code == 200
    assert "Check before you pay" in check.text   # scam checker page


def test_oversized_request_body_rejected(client):
    # 9 MB > the 8 MB default cap -> 413 before any handler runs.
    resp = client.post(
        "/api/v1/analysis",
        content=b"x" * (9 * 1024 * 1024),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413


@pytest.mark.parametrize(
    "payload",
    [
        {},                                   # missing field
        {"text": ""},                         # empty after strip
        {"text": "   "},                      # whitespace only
        {"text": "x" * 5001},                 # over the 5000-char cap
        {"text": 123},                        # wrong type
    ],
)
def test_analysis_input_validation(client, payload):
    resp = client.post("/api/v1/analysis", json=payload)
    assert resp.status_code == 422


def test_analysis_malformed_json_is_422_not_500(client):
    resp = client.post(
        "/api/v1/analysis",
        content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422


def test_report_endpoint_is_rate_limited():
    """The limiter registry must carry the reports endpoint (10/minute)."""
    from backend.app.core.rate_limit import limiter

    limits = limiter._route_limits.get(
        "backend.app.routes.reports.create_report", []
    )
    assert limits, "POST /api/v1/reports has no rate limit attached"
    assert any("minute" in str(l.limit) for l in limits)
