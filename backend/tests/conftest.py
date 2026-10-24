"""Shared fixtures for the backend integration tests.

Runs against the PostgreSQL DATABASE_URL from backend/.env (the Neon demo DB).
Every test uses throwaway `pytest_*` accounts; an autouse fixture scrubs all
rows the tests created after each test. For full isolation, point DATABASE_URL
at a dedicated Neon branch before running pytest.
"""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]

# Rate limiting must never interfere with integration tests.
os.environ["RATE_LIMIT_AUTH"] = "1000/minute"


def _postgres_url() -> str:
    """Prefer a Postgres URL from the environment; else fall back to backend/.env.

    Some sandboxes export a non-Postgres DATABASE_URL (e.g. file:...) - this
    repo is PostgreSQL-only, so in that case the .env value wins.
    """
    current = os.environ.get("DATABASE_URL", "")
    if current.startswith("postgres"):
        return current
    for line in (BACKEND_DIR / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("DATABASE_URL="):
            return line.partition("=")[2].strip()
    raise RuntimeError("No PostgreSQL DATABASE_URL available for tests")


os.environ["DATABASE_URL"] = _postgres_url()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from backend.app.db.session import SessionLocal  # noqa: E402
from backend.app.main import app  # noqa: E402

TEST_USER_IDS = (
    "(SELECT user_id FROM users WHERE email LIKE 'pytest_%' "
    "OR email LIKE 'deleted-%@anonymised.invalid')"
)


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def scrub_test_rows():
    """Delete every row the tests created (accounts, reports, audits, ...)."""
    yield
    with SessionLocal() as db:
        db.execute(
            text(
                "DELETE FROM scam_report_reviews WHERE report_id IN "
                f"(SELECT report_id FROM scam_reports WHERE reporter_id IN {TEST_USER_IDS}) "
                f"OR reviewer_id IN {TEST_USER_IDS}"
            )
        )
        db.execute(text(f"DELETE FROM scam_reports WHERE reporter_id IN {TEST_USER_IDS}"))
        # Assessments created by /analysis during tests (evidence cascades).
        db.execute(
            text(
                "DELETE FROM assessment_evidence WHERE assessment_id IN "
                f"(SELECT assessment_id FROM risk_assessments WHERE user_id IN {TEST_USER_IDS})"
            )
        )
        db.execute(text(f"DELETE FROM risk_assessments WHERE user_id IN {TEST_USER_IDS}"))
        db.execute(
            text(
                f"DELETE FROM educational_resources WHERE created_by IN {TEST_USER_IDS} "
                "OR slug LIKE 'pytest-%'"
            )
        )
        db.execute(
            text(
                f"DELETE FROM user_privacy_requests WHERE user_id IN {TEST_USER_IDS} "
                f"OR processed_by IN {TEST_USER_IDS}"
            )
        )
        db.execute(text(f"DELETE FROM audit_logs WHERE actor_user_id IN {TEST_USER_IDS}"))
        db.execute(
            text(
                "DELETE FROM login_attempts WHERE email_attempted LIKE 'pytest_%' "
                f"OR user_id IN {TEST_USER_IDS}"
            )
        )
        db.execute(text(f"DELETE FROM refresh_tokens WHERE user_id IN {TEST_USER_IDS}"))
        db.execute(text(f"DELETE FROM user_roles WHERE user_id IN {TEST_USER_IDS}"))
        db.execute(text(f"DELETE FROM users WHERE email LIKE 'pytest_%' OR email LIKE 'deleted-%@anonymised.invalid'"))
        db.commit()


@pytest.fixture
def unique_email() -> str:
    return f"pytest_{os.urandom(5).hex()}@example.com"


@pytest.fixture
def make_user(client):
    """Register + login a throwaway USER account. Returns headers + tokens."""

    def _make(password: str = "Str0ngPassw0rd!"):
        email = f"pytest_{os.urandom(5).hex()}@example.com"
        resp = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "full_name": "Pytest User"},
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        return {
            "email": email,
            "password": password,
            "headers": {"Authorization": f"Bearer {data['access_token']}"},
            "data": data,
        }

    return _make


@pytest.fixture
def make_admin(client, make_user):
    """Register a user, promote to ADMIN directly in the DB, re-login."""

    def _make():
        account = make_user()
        with SessionLocal() as db:
            db.execute(
                text(
                    "INSERT INTO user_roles (user_id, role_id) "
                    "SELECT u.user_id, r.role_id FROM users u, roles r "
                    "WHERE u.email = :e AND r.role_name = 'ADMIN' "
                    "ON CONFLICT DO NOTHING"
                ),
                {"e": account["email"]},
            )
            db.commit()
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": account["email"], "password": account["password"]},
        )
        assert resp.status_code == 200, resp.text
        account["headers"] = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        account["data"] = resp.json()
        return account

    return _make
