"""Integration tests: admin-only audit trail with working filters."""

import os


def _report(client, account) -> dict:
    resp = client.post(
        "/api/v1/reports",
        json={
            "title": f"Audit trail test {os.urandom(2).hex()}",
            "description": "Filing a report so the audit trail has a CREATE row to find.",
            "channel": "OTHER",
        },
        headers=account["headers"],
    )
    assert resp.status_code == 201
    return resp.json()


def test_audit_requires_admin(client, make_user):
    user = make_user()
    resp = client.get("/api/v1/audit", headers=user["headers"])
    assert resp.status_code == 403


def test_audit_requires_auth(client):
    assert client.get("/api/v1/audit").status_code == 401


def test_audit_records_logins_and_actions(client, make_user, make_admin):
    user = make_user()
    report = _report(client, user)
    admin = make_admin()  # a login for the admin is recorded too

    by_action = client.get("/api/v1/audit?action=LOGIN", headers=admin["headers"])
    assert by_action.status_code == 200
    items = by_action.json()["items"]
    assert items, "expected at least one LOGIN audit row"
    assert all(item["action"] == "LOGIN" for item in items)

    by_entity = client.get(
        "/api/v1/audit?entity_type=scam_report", headers=admin["headers"]
    )
    assert by_entity.status_code == 200
    assert report["report_id"] in [
        item["entity_id"] for item in by_entity.json()["items"]
    ]

    by_actor = client.get(
        f"/api/v1/audit?actor_user_id={user['data']['user']['user_id']}",
        headers=admin["headers"],
    )
    assert by_actor.status_code == 200
    assert by_actor.json()["total"] >= 1  # the report CREATE row
