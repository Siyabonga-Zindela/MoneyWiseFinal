"""Integration tests: POPIA requests, admin processing, account anonymisation, export."""

import os

from sqlalchemy import text

from backend.app.db.session import SessionLocal


def _report(client, account) -> dict:
    resp = client.post(
        "/api/v1/reports",
        json={
            "title": f"Privacy export test {os.urandom(2).hex()}",
            "description": "A report used to verify that the data export lists my own reports.",
            "channel": "EMAIL",
        },
        headers=account["headers"],
    )
    assert resp.status_code == 201
    return resp.json()


def test_deletion_request_anonymises_account(client, make_user, make_admin):
    user, admin = make_user(), make_admin()

    created = client.post(
        "/api/v1/privacy/requests",
        json={"request_type": "ACCOUNT_DELETION", "details": "Please remove my data."},
        headers=user["headers"],
    )
    assert created.status_code == 201, created.text
    request_id = created.json()["request_id"]
    assert created.json()["status"] == "RECEIVED"

    mine = client.get("/api/v1/privacy/requests", headers=user["headers"])
    assert [r["request_id"] for r in mine.json()] == [request_id]

    assert (
        client.patch(
            f"/api/v1/privacy/requests/{request_id}",
            json={"status": "IN_PROGRESS"},
            headers=admin["headers"],
        ).status_code
        == 200
    )
    done = client.patch(
        f"/api/v1/privacy/requests/{request_id}",
        json={"status": "COMPLETED", "retention_note": "audit logs retained for security"},
        headers=admin["headers"],
    )
    assert done.status_code == 200

    # The old token must now be refused (status is DELETED).
    assert client.get("/api/v1/auth/me", headers=user["headers"]).status_code == 403

    with SessionLocal() as db:
        row = db.execute(
            text(
                "SELECT u.email, u.status::text, u.full_name FROM users u "
                "JOIN user_privacy_requests p ON p.user_id = u.user_id "
                "WHERE p.request_id = :r"
            ),
            {"r": request_id},
        ).fetchone()
    assert row is not None
    assert row[0].startswith("deleted-")
    assert row[1] == "DELETED"
    assert row[2] is None  # personal fields scrubbed


def test_data_export_lists_my_data(client, make_user):
    user = make_user()
    report = _report(client, user)

    export = client.get("/api/v1/privacy/export", headers=user["headers"])
    assert export.status_code == 200
    body = export.json()
    assert body["profile"]["email"] == user["email"]
    assert report["report_id"] in [r["report_id"] for r in body["reports"]]


def test_admin_queue_lists_requests(client, make_user, make_admin):
    user, admin = make_user(), make_admin()
    created = client.post(
        "/api/v1/privacy/requests",
        json={"request_type": "DATA_EXPORT"},
        headers=user["headers"],
    )
    assert created.status_code == 201

    queue = client.get("/api/v1/privacy/requests/all", headers=admin["headers"])
    assert queue.status_code == 200
    assert any(
        item["request_id"] == created.json()["request_id"]
        for item in queue.json()["items"]
    )
