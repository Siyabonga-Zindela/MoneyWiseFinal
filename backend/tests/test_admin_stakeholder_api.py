"""Tests for the admin + stakeholder endpoints that serve the new UI pages.

Covers the full frontend integration surface:
  - GET  /api/v1/admin/reports        (dashboard list, UI dialect)
  - PATCH /api/v1/admin/reports/{id}  (status + note -> review rows/409s)
  - GET  /api/v1/admin/summary        (new_reports counter)
  - stakeholder CRUD                  (create/invited, suspend, resend, delete)
  - /api/v1/stakeholder/offers CRUD   (create, list, 3-column PATCH, delete)
  - anonymous report submission       (popup on the public homepage)
"""

import os

from sqlalchemy import text

from backend.app.db.session import SessionLocal


def _promote(client, email: str, role: str):
    """Give an existing account a role directly in the DB."""
    with SessionLocal() as db:
        db.execute(
            text(
                "INSERT INTO user_roles (user_id, role_id) "
                "SELECT u.user_id, r.role_id FROM users u, roles r "
                "WHERE u.email = :e AND r.role_name = :r "
                "ON CONFLICT DO NOTHING"
            ),
            {"e": email, "r": role},
        )
        db.commit()


def _report_payload(title: str, **overrides) -> dict:
    payload = {
        "title": title,
        "description": "pytest body: Invest R1000, get R5000, invite 3 friends.",
        "phishing_type": "Investment or pyramid scheme",
        "risk_level": "high",
        "sender": "+27 82 555 0000",
        "amount_asked": 1000,
        "amount_promised": 5000,
    }
    payload.update(overrides)
    return payload


# ---- anonymous popup submission ---------------------------------------------


def test_anonymous_popup_report_is_accepted(client):
    """The homepage popup has no account - the report must still land."""
    resp = client.post(
        "/api/v1/reports",
        json=_report_payload("pytest-anon popup report"),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["reporter_id"] is None
    assert body["status"] == "SUBMITTED"
    assert body["risk_level"] == "HIGH"


# ---- admin: reports ----------------------------------------------------------


def test_admin_reports_list_and_review_flow(client, make_admin, make_user):
    admin = make_admin()
    user = make_user()

    created = client.post(
        "/api/v1/reports",
        json=_report_payload("pytest-reviewed report"),
        headers=user["headers"],
    )
    assert created.status_code == 201
    report_id = created.json()["report_id"]

    listing = client.get(
        "/api/v1/admin/reports",
        headers=admin["headers"],
    )
    assert listing.status_code == 200, listing.text
    rows = listing.json()
    row = next(r for r in rows if r["id"] == report_id)
    assert row["status"] == "new"
    assert row["risk_level"] == "high"
    assert row["amount_asked"] == 1000
    assert row["message"].startswith("pytest body:")
    assert row["date_received"] and row["submitted_at"]

    # Confirm -> APPROVED decision row + final status.
    saved = client.patch(
        f"/api/v1/admin/reports/{report_id}",
        json={"status": "confirmed", "note": "Verified pyramid pitch"},
        headers=admin["headers"],
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["status"] == "confirmed"
    assert saved.json()["note"] == "Verified pyramid pitch"

    # A finalised report cannot change again (409) - append-only integrity.
    again = client.patch(
        f"/api/v1/admin/reports/{report_id}",
        json={"status": "dismissed", "note": "nope"},
        headers=admin["headers"],
    )
    assert again.status_code == 409


def test_admin_patch_requires_admin(client, make_user):
    user = make_user()
    created = client.post(
        "/api/v1/reports",
        json=_report_payload("pytest-unauthorised"),
        headers=user["headers"],
    )
    report_id = created.json()["report_id"]

    denied_list = client.get("/api/v1/admin/reports", headers=user["headers"])
    assert denied_list.status_code == 403

    denied_patch = client.patch(
        f"/api/v1/admin/reports/{report_id}",
        json={"status": "reviewing", "note": ""},
        headers=user["headers"],
    )
    assert denied_patch.status_code in (401, 403)

    anonymous = client.get("/api/v1/admin/reports")
    assert anonymous.status_code in (401, 403)


def test_admin_summary_counts_new_reports(client, make_admin, make_user):
    admin = make_admin()
    user = make_user()
    client.post("/api/v1/reports", json=_report_payload("pytest-summary counter"), headers=user["headers"])

    summary = client.get("/api/v1/admin/summary", headers=admin["headers"])
    assert summary.status_code == 200
    assert summary.json()["new_reports"] >= 1


# ---- admin: stakeholders ------------------------------------------------------


def test_stakeholder_lifecycle(client, make_admin):
    admin = make_admin()
    email = f"pytest_{os.urandom(5).hex()}@partner.example"

    created = client.post(
        "/api/v1/admin/stakeholders",
        json={
            "name": "Test Partner",
            "email": email,
            "organisation": "Test Bank",
            "org_type": "bank",
            "access": "review",
            "alerts": "high",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["status"] == "invited"
    assert body["access"] == "review"
    temp_password = body["temporary_password"]
    assert temp_password and len(temp_password) >= 8

    duplicate = client.post(
        "/api/v1/admin/stakeholders",
        json={"name": "X", "email": email, "organisation": "Y", "org_type": "other"},
        headers=admin["headers"],
    )
    assert duplicate.status_code == 409

    # The invited stakeholder can actually sign in with the temporary password.
    login = client.post("/api/v1/auth/login", json={"email": email, "password": temp_password})
    assert login.status_code == 200, login.text
    assert "STAKEHOLDER" in login.json()["user"]["roles"]
    stakeholder_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    # Suspend -> stakeholder can no longer sign in.
    suspended = client.patch(
        f"/api/v1/admin/stakeholders/{body['id']}",
        json={"status": "suspended"},
        headers=admin["headers"],
    )
    assert suspended.status_code == 200
    assert suspended.json()["status"] == "suspended"
    locked_out = client.post("/api/v1/auth/login", json={"email": email, "password": temp_password})
    assert locked_out.status_code == 403

    # Reactivate via 'invited' -> fresh invitation state, old password still valid.
    reactivated = client.patch(
        f"/api/v1/admin/stakeholders/{body['id']}",
        json={"status": "invited"},
        headers=admin["headers"],
    )
    assert reactivated.status_code == 200
    assert reactivated.json()["status"] == "invited"
    assert client.post(
        "/api/v1/auth/login", json={"email": email, "password": temp_password}
    ).status_code == 200

    # Resend re-issues the password: the new one works, the old one is gone.
    resent = client.post(
        f"/api/v1/admin/stakeholders/{body['id']}/resend",
        headers=admin["headers"],
    )
    assert resent.status_code == 200, resent.text
    new_password = resent.json()["temporary_password"]
    assert new_password != temp_password
    assert client.post(
        "/api/v1/auth/login", json={"email": email, "password": new_password}
    ).status_code == 200
    assert client.post(
        "/api/v1/auth/login", json={"email": email, "password": temp_password}
    ).status_code == 401

    # Soft delete: gone from the list, login refused.
    removed = client.delete(f"/api/v1/admin/stakeholders/{body['id']}", headers=admin["headers"])
    assert removed.status_code == 200
    listing = client.get("/api/v1/admin/stakeholders", headers=admin["headers"])
    assert all(row["id"] != body["id"] for row in listing.json())
    assert client.post(
        "/api/v1/auth/login", json={"email": email, "password": new_password}
    ).status_code in (401, 403)


def test_stakeholder_endpoints_require_admin(client, make_user):
    user = make_user()
    denied = client.get("/api/v1/admin/stakeholders", headers=user["headers"])
    assert denied.status_code in (401, 403)


# ---- stakeholder offers --------------------------------------------------------


def _offer_payload(**overrides) -> dict:
    payload = {
        "product_name": "pytest 12 Month Fixed Deposit",
        "product_category": "Fixed deposit",
        "description": "pytest offer body for integration tests.",
        "min_investment": 1000,
        "max_investment": 500000,
        "indicative_return_range": "7.5% - 8.5% p.a.",
    }
    payload.update(overrides)
    return payload


def test_stakeholder_offer_crud(client, make_admin):
    admin = make_admin()
    email = f"pytest_{os.urandom(5).hex()}@partner.example"

    created = client.post(
        "/api/v1/admin/stakeholders",
        json={
            "name": "Offer Partner",
            "email": email,
            "organisation": "Offer Bank",
            "org_type": "bank",
        },
        headers=admin["headers"],
    )
    temp_password = created.json()["temporary_password"]
    login = client.post("/api/v1/auth/login", json={"email": email, "password": temp_password})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    empty = client.get("/api/v1/stakeholder/offers", headers=headers)
    assert empty.status_code == 200 and empty.json() == []

    offer = client.post("/api/v1/stakeholder/offers", json=_offer_payload(), headers=headers)
    assert offer.status_code == 201, offer.text
    body = offer.json()
    assert body["currency"] == "ZAR"
    assert float(body["min_investment"]) == 1000

    listed = client.get("/api/v1/stakeholder/offers", headers=headers)
    assert [row["id"] for row in listed.json()] == [body["id"]]

    # Only the 3 editable columns change; everything else is rejected shape-wise.
    patched = client.patch(
        f"/api/v1/stakeholder/offers/{body['id']}",
        json={"min_investment": 2000, "indicative_return_range": "8% - 9% p.a."},
        headers=headers,
    )
    assert patched.status_code == 200
    assert float(patched.json()["min_investment"]) == 2000

    bad = client.patch(
        f"/api/v1/stakeholder/offers/{body['id']}",
        json={"min_investment": 999999999},
        headers=headers,
    )
    assert bad.status_code == 422  # max < min

    deleted = client.delete(f"/api/v1/stakeholder/offers/{body['id']}", headers=headers)
    assert deleted.status_code == 200
    assert client.get("/api/v1/stakeholder/offers", headers=headers).json() == []


def test_offers_reject_non_stakeholders(client, make_user, make_admin):
    user = make_user()
    denied = client.get("/api/v1/stakeholder/offers", headers=user["headers"])
    assert denied.status_code in (401, 403)

    # A fresh USER account cannot create offers either.
    offer = client.post("/api/v1/stakeholder/offers", json=_offer_payload(), headers=user["headers"])
    assert offer.status_code in (401, 403)


def test_stakeholder_login_lands_on_offers_role(client, make_admin):
    """The role the login page routes on is present end-to-end."""
    admin = make_admin()
    email = f"pytest_{os.urandom(5).hex()}@partner.example"
    created = client.post(
        "/api/v1/admin/stakeholders",
        json={"name": "Role Partner", "email": email, "organisation": "Role Org", "org_type": "other"},
        headers=admin["headers"],
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": created.json()["temporary_password"]},
    )
    roles = login.json()["user"]["roles"]
    assert "STAKEHOLDER" in roles and "ADMIN" not in roles
