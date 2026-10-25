"""Tests for the UI-alignment work (migration 0002):

- /analysis persists a risk_assessments row and returns assessment_id + score
- the report popup's field names (phishing_type/message/risk_level/...) land
  in scam_reports and auto-derive channel/title/occurred_at
- multipart reports accept a PNG screenshot and reject other file types
- a report can link back to the assessment that produced it
"""

import struct
import zlib

from sqlalchemy import text


def _tiny_png() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        block = struct.pack(">I", len(data)) + tag + data
        return block + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def test_analysis_persists_assessment_with_score(client, make_user):
    account = make_user()
    resp = client.post(
        "/api/v1/analysis",
        json={"text": "Guaranteed profit! Act now and pay in cryptocurrency."},
        headers=account["headers"],
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["assessment_id"] is not None
    assert data["category"] == "high"
    assert data["risk_score"] >= 80
    codes = {i["code"] for i in data["indicators"]}
    assert {"guaranteed_returns", "urgent_payment", "unusual_payment_method"} <= codes
    # every indicator keeps its matched text -> "what led to the output"
    assert all(i["evidence"] for i in data["indicators"])


def test_popup_shape_report_saves_ui_fields(client, make_user):
    account = make_user()
    payload = {
        "phishing_type": "SMS phishing (smishing)",
        "message": "You have won R250 000! Send R500 admin fee to release your prize money today.",
        "risk_level": "high",
        "date_received": "2026-10-01",
        "sender": "+27 82 000 0000",
        "amount_asked": "500.00",
        "amount_promised": "250000.00",
    }
    resp = client.post("/api/v1/reports", json=payload, headers=account["headers"])
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert report["phishing_type"] == "SMS phishing (smishing)"
    assert report["channel"] == "SMS"  # derived from phishing_type
    assert report["risk_level"] == "HIGH"
    assert float(report["amount_asked"]) == 500.00
    assert float(report["amount_promised"]) == 250000.00
    assert report["reported_contact"] == "+27 82 000 0000"
    assert report["occurred_at"].startswith("2026-10-01")
    assert report["title"] == "SMS phishing (smishing)"
    assert report["status"] == "SUBMITTED"


def test_popup_report_links_to_assessment(client, make_user):
    account = make_user()
    analysis = client.post(
        "/api/v1/analysis",
        json={"text": "Earn by recruiting new members, 100% return guaranteed."},
        headers=account["headers"],
    ).json()
    resp = client.post(
        "/api/v1/reports",
        json={
            "phishing_type": "Investment or pyramid scheme",
            "message": "They told me to recruit new members to unlock my 100% return payout.",
            "risk_level": "unsure",
            "assessment_id": analysis["assessment_id"],
        },
        headers=account["headers"],
    )
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert report["assessment_id"] == analysis["assessment_id"]
    assert report["risk_level"] == "INCONCLUSIVE"  # "unsure"


def test_multipart_report_with_screenshot(client, make_user):
    account = make_user()
    resp = client.post(
        "/api/v1/reports",
        headers=account["headers"],
        files={"screenshot": ("proof.png", _tiny_png(), "image/png")},
        data={
            "phishing_type": "Fake website or link",
            "message": "This website asked for my banking PIN to verify my account. The link looks fake.",
            "risk_level": "medium",
        },
    )
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert report["screenshot_path"] and report["screenshot_path"].endswith(".png")
    assert report["channel"] == "WEBSITE"
    assert report["risk_level"] == "MEDIUM"

    # the stored file actually exists under backend/uploads/reports/
    from pathlib import Path

    backend_dir = Path(__file__).resolve().parents[1]
    assert (backend_dir / report["screenshot_path"]).is_file()


def test_multipart_rejects_non_image(client, make_user):
    account = make_user()
    resp = client.post(
        "/api/v1/reports",
        headers=account["headers"],
        files={"screenshot": ("evil.exe", b"MZfake", "application/x-msdownload")},
        data={
            "phishing_type": "Email phishing",
            "message": "Please confirm your identity by replying with your ID number today.",
        },
    )
    assert resp.status_code == 415


def test_risk_level_validation(client, make_user):
    account = make_user()
    resp = client.post(
        "/api/v1/reports",
        json={
            "phishing_type": "Email phishing",
            "risk_level": "extreme",
            "message": "This is a test message long enough to pass validation checks.",
        },
        headers=account["headers"],
    )
    assert resp.status_code == 422
    assert "risk_level" in resp.text
