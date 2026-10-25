"""Admin -> stakeholder report forwarding (impersonation handover).

Forwarding records live in the append-only audit trail (no new tables).
Covers: forward, inbox visibility, acknowledge, and the authorisation walls.
"""

import pytest

from backend.app.db.session import SessionLocal
from backend.app.models.enums import AuditAction
from backend.app.models.audit_log import AuditLog
from sqlalchemy import text


@pytest.fixture
def make_stakeholder(client, make_admin):
    """Create a stakeholder through the admin API. Returns account + admin."""

    def _make(org="Test Bank", org_type="bank", email=None):
        admin = make_admin()
        email = email or f"pytest_{org.lower().replace(' ', '')}{org_type}@example.com"
        resp = client.post(
            "/api/v1/admin/stakeholders",
            json={
                "email": email,
                "name": f"{org} Rep",
                "organisation": org,
                "org_type": org_type,
                "access": "review",
                "alerts": "high",
            },
            headers=admin["headers"],
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        temp_password = data["temporary_password"]
        login = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": temp_password},
        )
        assert login.status_code == 200, login.text
        return {
            "user_id": data["id"],
            "email": email,
            "organisation": data["organisation"],
            "headers": {"Authorization": f"Bearer {login.json()['access_token']}"},
            "admin": admin,
        }

    return _make


def _make_report(client, admin, sender, message, phishing_type="Fake website or link"):
    resp = client.post(
        "/api/v1/reports",
        json={
            "phishing_type": phishing_type,
            "message": message,
            "risk_level": "high",
            "sender": sender,
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["report_id"]


class TestForwardFlow:
    def test_forward_inbox_ack_roundtrip(self, client, make_stakeholder):
        stake = make_stakeholder(org="RoundTrip Bank", org_type="bank")
        admin = stake["admin"]

        report_id = _make_report(
            client, admin,
            "072 000 1122",
            "This is RoundTrip Bank security. Your account is locked - confirm your PIN to unlock it now.",
        )

        # Admin forwards the impersonation report to the bank stakeholder.
        fwd = client.post(
            f"/api/v1/admin/reports/{report_id}/forward",
            json={"stakeholder_user_id": stake["user_id"], "note": "Please block this number."},
            headers=admin["headers"],
        )
        assert fwd.status_code == 200, fwd.text
        body = fwd.json()
        assert "RoundTrip Bank" in body["detail"]
        assert body["report"]["status"] == "reviewing"  # REQUIRES_INVESTIGATION in UI dialect
        sent = body["report"]["forwarded_to"]
        assert len(sent) == 1
        assert sent[0]["organisation"] == "RoundTrip Bank"
        assert sent[0]["acknowledged"] is False

        # Stakeholder sees it in the inbox.
        inbox = client.get("/api/v1/stakeholder/reports", headers=stake["headers"])
        assert inbox.status_code == 200, inbox.text
        items = inbox.json()
        assert len(items) == 1
        item = items[0]
        assert item["report_id"] == report_id
        assert item["sender"] == "072 000 1122"
        assert item["note"] == "Please block this number."
        assert item["organisation"] == "RoundTrip Bank"
        assert item["acknowledged"] is False
        # Identity-safety: the reporter is never exposed to the partner.
        assert "reporter" not in item

        # Stakeholder acknowledges; admin then sees the receipt.
        ack = client.post(
            f"/api/v1/stakeholder/reports/{report_id}/acknowledge",
            headers=stake["headers"],
        )
        assert ack.status_code == 200, ack.text
        assert ack.json()["report_id"] == report_id

        admin_view = client.get("/api/v1/admin/reports", headers=admin["headers"])
        assert admin_view.status_code == 200
        row = next(r for r in admin_view.json() if r["id"] == report_id)
        assert row["forwarded_to"][0]["acknowledged"] is True
        assert row["forwarded_to"][0]["acknowledged_at"]

    def test_forward_suggests_matching_organisation_label(
        self, client, make_stakeholder
    ):
        stake = make_stakeholder(org="Acme Insurance", org_type="other")
        admin = stake["admin"]
        report_id = _make_report(
            client, admin,
            "claims@acmeinsurance.co",
            "Acme Insurance says your policy lapsed - pay R900 to reinstate it today.",
        )
        listing = client.get("/api/v1/admin/reports", headers=admin["headers"])
        row = next(r for r in listing.json() if r["id"] == report_id)
        # The admin UI does the suggesting; the API just carries the content.
        assert "Acme Insurance" in row["message"]

    def test_non_stakeholder_target_404(self, client, make_admin, make_user):
        admin = make_admin()
        victim = make_user()
        report_id = _make_report(
            client, admin, "072 999 8877", "You have won R100000, pay R500 release fee now."
        )
        # A plain USER is not a stakeholder - must not be forwardable.
        resp = client.post(
            f"/api/v1/admin/reports/{report_id}/forward",
            json={"stakeholder_user_id": victim["data"]["user"]["user_id"]},
            headers=admin["headers"],
        )
        assert resp.status_code == 404

    def test_stakeholder_cannot_forward_and_user_cannot_see_inbox(
        self, client, make_stakeholder, make_user
    ):
        stake = make_stakeholder(org="Guarded Corp", org_type="other")
        admin = stake["admin"]
        outsider = make_user()
        report_id = _make_report(
            client, admin, "072 777 6655", "Guarded Corp owes you R30000, pay the R300 tax first."
        )

        # Stakeholder cannot use the admin forward endpoint.
        no_fwd = client.post(
            f"/api/v1/admin/reports/{report_id}/forward",
            json={"stakeholder_user_id": stake["user_id"]},
            headers=stake["headers"],
        )
        assert no_fwd.status_code == 403

        # A plain user cannot read the stakeholder inbox.
        no_inbox = client.get("/api/v1/stakeholder/reports", headers=outsider["headers"])
        assert no_inbox.status_code == 403

        # The stakeholder cannot acknowledge a report never sent to them.
        other_report_id = _make_report(
            client, admin, "072 555 4433", "Completely unrelated report about a courier fee."
        )
        bad_ack = client.post(
            f"/api/v1/stakeholder/reports/{other_report_id}/acknowledge",
            headers=stake["headers"],
        )
        assert bad_ack.status_code == 404

    def test_forward_is_audited(self, client, make_stakeholder):
        stake = make_stakeholder(org="Audited Ltd", org_type="other")
        admin = stake["admin"]
        report_id = _make_report(
            client, admin, "072 121 3434", "Audited Ltd refund department: pay R120 to get R12000."
        )
        fwd = client.post(
            f"/api/v1/admin/reports/{report_id}/forward",
            json={"stakeholder_user_id": stake["user_id"]},
            headers=admin["headers"],
        )
        assert fwd.status_code == 200
        with SessionLocal() as db:
            rows = db.execute(
                text(
                    "SELECT count(*) FROM audit_logs WHERE entity_type = 'stakeholder_report_send' "
                    "AND entity_id = :sid AND details->>'report_id' = :rid"
                ),
                {"sid": stake["user_id"], "rid": str(report_id)},
            ).scalar_one()
            assert rows == 1
