"""Integration tests: education centre (public reading + admin publishing)."""

import os

from backend.app.db.session import SessionLocal


def test_public_list_only_published(client):
    listing = client.get("/api/v1/education")
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert len(items) >= 1  # baseline seed ships 5 published English articles
    assert all(item["is_published"] for item in items)


def test_admin_create_then_publish(client, make_admin):
    admin = make_admin()
    marker = os.urandom(2).hex()
    created = client.post(
        "/api/v1/education",
        json={
            "title": f"Pytest warning signs {marker}",
            "topic": "INVESTMENT_PROMISES",
            "summary": "How to spot unrealistic guaranteed-return promises.",
            "content": (
                "Guaranteed high returns with no risk are the classic warning "
                "sign of investment fraud. Always verify the entity with the "
                "FSCA before you pay anything at all."
            ),
            "is_published": False,
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["slug"].startswith("pytest-")

    # Unpublished => hidden from the public list and detail endpoint.
    assert client.get(f"/api/v1/education/{body['slug']}").status_code == 404
    listing = client.get("/api/v1/education?topic=INVESTMENT_PROMISES")
    assert all(item["slug"] != body["slug"] for item in listing.json()["items"])

    patched = client.patch(
        f"/api/v1/education/{body['resource_id']}",
        json={"is_published": True},
        headers=admin["headers"],
    )
    assert patched.status_code == 200
    assert client.get(f"/api/v1/education/{body['slug']}").status_code == 200


def test_non_admin_cannot_create(client, make_user):
    user = make_user()
    resp = client.post(
        "/api/v1/education",
        json={
            "title": "Should not exist",
            "topic": "OTHER",
            "summary": "A regular user must not publish content.",
            "content": "This content must never be created by a non-admin account.",
        },
        headers=user["headers"],
    )
    assert resp.status_code == 403


def test_seed_articles_survive_tests(client):
    """The 5 baseline seed articles must never be touched by test cleanup."""
    with SessionLocal() as db:
        count = db.execute(
            __import__("sqlalchemy").text(
                "SELECT count(*) FROM educational_resources WHERE slug LIKE '%-en'"
            )
        ).scalar()
    assert count >= 5
