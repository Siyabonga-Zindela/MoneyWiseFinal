"""Integration tests: admin review decisions and status transitions."""

import os


def _file_report(client, account) -> dict:
    resp = client.post(
        "/api/v1/reports",
        json={
            "title": f"Investment scam whatsapp group {os.urandom(2).hex()}",
            "description": (
                "A WhatsApp group promises 40 percent monthly returns from a "
                "forex trader. Members are pressured to recruit friends quickly."
            ),
            "channel": "WHATSAPP",
        },
        headers=account["headers"],
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_non_admin_cannot_review(client, make_user):
    user = make_user()
    report = _file_report(client, user)
    resp = client.post(
        f"/api/v1/reports/{report['report_id']}/reviews",
        json={"action": "APPROVED"},
        headers=user["headers"],
    )
    assert resp.status_code == 403


def test_admin_decision_updates_report_status(client, make_user, make_admin):
    user, admin = make_user(), make_admin()
    report = _file_report(client, user)

    resp = client.post(
        f"/api/v1/reports/{report['report_id']}/reviews",
        json={"action": "APPROVED", "notes": "Confirmed with official sources"},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["action"] == "APPROVED"

    got = client.get(f"/api/v1/reports/{report['report_id']}", headers=user["headers"])
    assert got.json()["status"] == "APPROVED"


def test_final_decision_is_immutable(client, make_user, make_admin):
    user, admin = make_user(), make_admin()
    report = _file_report(client, user)
    client.post(
        f"/api/v1/reports/{report['report_id']}/reviews",
        json={"action": "REJECTED"},
        headers=admin["headers"],
    )
    second = client.post(
        f"/api/v1/reports/{report['report_id']}/reviews",
        json={"action": "APPROVED"},
        headers=admin["headers"],
    )
    assert second.status_code == 409


def test_owner_sees_review_trail(client, make_user, make_admin):
    user, admin = make_user(), make_admin()
    report = _file_report(client, user)
    client.post(
        f"/api/v1/reports/{report['report_id']}/reviews",
        json={"action": "REQUIRES_INVESTIGATION", "notes": "Need the FSP number"},
        headers=admin["headers"],
    )
    trail = client.get(
        f"/api/v1/reports/{report['report_id']}/reviews", headers=user["headers"]
    )
    assert trail.status_code == 200
    items = trail.json()
    assert len(items) == 1
    assert items[0]["action"] == "REQUIRES_INVESTIGATION"
    assert items[0]["notes"] == "Need the FSP number"
