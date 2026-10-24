"""Integration tests: scam report filing, duplicate linking, access control."""

import os


def _payload(title: str = "Phishing SMS asking for my OTP"):
    return {
        "title": f"{title} {os.urandom(2).hex()}",
        "description": (
            "I received an SMS claiming my bank account will be closed unless I "
            "confirm my OTP on a strange link. It looks exactly like my bank."
        ),
        "channel": "SMS",
    }


def test_create_and_read_own_report(client, make_user):
    account = make_user()
    resp = client.post("/api/v1/reports", json=_payload(), headers=account["headers"])
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert report["status"] == "SUBMITTED"
    assert report["is_public"] is False
    got = client.get(
        f"/api/v1/reports/{report['report_id']}", headers=account["headers"]
    )
    assert got.status_code == 200
    assert got.json()["title"] == report["title"]


def test_reports_require_auth(client):
    assert client.post("/api/v1/reports", json=_payload()).status_code == 401


def test_duplicate_content_is_linked_not_merged(client, make_user):
    first, second = make_user(), make_user()
    # Byte-identical payload (no random suffix) - normalisation must match it.
    payload = {
        "title": "Identical duplicate content report",
        "description": (
            "I received an SMS claiming my bank account will be closed unless I "
            "confirm my OTP on a strange link. It looks exactly like my bank."
        ),
        "channel": "SMS",
    }
    r1 = client.post("/api/v1/reports", json=payload, headers=first["headers"]).json()
    r2 = client.post("/api/v1/reports", json=payload, headers=second["headers"]).json()
    # Identical normalised content -> the second report LINKS to the original.
    assert r2["duplicate_of_id"] == r1["report_id"]
    assert r2["report_id"] != r1["report_id"]


def test_user_cannot_read_others_report(client, make_user):
    owner, outsider = make_user(), make_user()
    report = client.post("/api/v1/reports", json=_payload(), headers=owner["headers"]).json()
    resp = client.get(
        f"/api/v1/reports/{report['report_id']}", headers=outsider["headers"]
    )
    assert resp.status_code == 403


def test_admin_scope_all_only_for_admins(client, make_user, make_admin):
    user, admin = make_user(), make_admin()
    client.post("/api/v1/reports", json=_payload(), headers=user["headers"])

    forbidden = client.get("/api/v1/reports?scope=all", headers=user["headers"])
    assert forbidden.status_code == 403

    everything = client.get("/api/v1/reports?scope=all", headers=admin["headers"])
    assert everything.status_code == 200
    assert everything.json()["total"] >= 1
