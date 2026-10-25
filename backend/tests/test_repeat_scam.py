"""Repeat-scam detection: unit tests for matching + API tests for escalation.

The escalation is deterministic (counts from scam_reports); the OpenRouter
enrichment is disabled in these tests so assertions stay fast and stable.
"""

import pytest

from backend.app.services.ai_analysis.openrouter_client import OpenRouterConfig
from backend.app.services.repeat_scam import (
    RepeatSignal,
    apply_repeat_signal,
    contact_keys,
)


@pytest.fixture(autouse=True)
def _no_ai(monkeypatch):
    """Keep the deterministic path under test - no OpenRouter calls."""
    monkeypatch.setattr(
        OpenRouterConfig,
        "from_env",
        classmethod(lambda cls, environ=None: cls(api_key="", model="test-model")),
        raising=True,
    )


class TestContactKeys:
    def test_phone_variants_share_key(self):
        # +27 country code, leading zero, spaces - all the same number.
        assert contact_keys("+27 72 123 4567") == contact_keys("0721234567")
        assert contact_keys("072 123 4567") == contact_keys("0721234567")

    def test_email_normalises_and_keeps_domain(self):
        keys = contact_keys("Alerts@FNB-Win.co.za")
        assert "alerts@fnb-win.co.za" in keys
        assert "url:fnb-win.co.za" in keys

    def test_url_host_key(self):
        keys = contact_keys("https://www.fnb-winner.co.za/claim?id=1")
        assert "url:fnb-winner.co.za" in keys

    def test_short_garbage_is_safe(self):
        assert contact_keys("") == []
        assert contact_keys(None) == []
        assert contact_keys("12") == []  # too short to match anything


class TestApplyRepeatSignal:
    def _assessment(self, category="low", score=10.0):
        from backend.app.services.ai_analysis.schemas import ScamAssessment

        return ScamAssessment(
            category=category, risk_score=score,
            indicators=[], explanation="x", next_steps=["a"], limitations="y",
        )

    def test_no_priors_unchanged(self):
        base = self._assessment()
        out = apply_repeat_signal(base, RepeatSignal())
        assert out.category == base.category
        assert out.risk_score == base.risk_score

    def test_single_contact_match_escalates_high(self):
        out = apply_repeat_signal(
            self._assessment(),
            RepeatSignal(prior_contact_reports=1, matched_label="number 721234567"),
        )
        assert out.category.value == "high"
        assert out.risk_score >= 85
        assert any(i.code == "repeat_offender" for i in out.indicators)

    def test_three_priors_score_95(self):
        out = apply_repeat_signal(
            self._assessment(),
            RepeatSignal(prior_contact_reports=3),
        )
        assert out.risk_score >= 95

    def test_high_baseline_not_lowered(self):
        out = apply_repeat_signal(
            self._assessment(category="high", score=100.0),
            RepeatSignal(prior_contact_reports=1),
        )
        assert out.risk_score == 100.0

    def test_single_provider_mention_only_medium(self):
        out = apply_repeat_signal(
            self._assessment(),
            RepeatSignal(prior_org_reports=1),
        )
        assert out.category.value == "medium"
        assert out.risk_score >= 50

    def test_two_provider_mentions_high(self):
        out = apply_repeat_signal(
            self._assessment(),
            RepeatSignal(prior_org_reports=2),
        )
        assert out.category.value == "high"
        assert out.risk_score >= 80


class TestAnalysisWithSender:
    def test_reported_sender_escalates_check(self, client, make_user, unique_email):
        account = make_user()
        h = account["headers"]

        # First report of this number.
        r1 = client.post(
            "/api/v1/reports",
            json={
                "phishing_type": "SMS phishing (smishing)",
                "message": "You have won R25000! Pay the R450 release fee to receive your prize today.",
                "risk_level": "high",
                "sender": "072 555 0101",
            },
            headers=h,
        )
        assert r1.status_code == 201, r1.text

        # A visitor checks a message from the SAME number (last-9 key match).
        check = client.post(
            "/api/v1/analysis",
            json={
                "text": "Hi! You have won R25000. Send us a R450 release fee to get your prize.",
                "sender": "+27725550101",
            },
        )
        assert check.status_code == 201, check.text
        data = check.json()
        assert data["category"] == "high"
        assert data["risk_score"] >= 85
        repeat = [i for i in data["indicators"] if i["code"] == "repeat_offender"]
        assert repeat, "repeat indicator missing"
        assert "already reported" in repeat[0]["explanation"]

        # Same number, no sender supplied -> no repeat indicator (old behaviour).
        plain = client.post(
            "/api/v1/analysis",
            json={"text": "Hi! You have won R25000. Send us a R450 release fee to get your prize."},
        )
        assert plain.status_code == 201
        plain_data = plain.json()
        assert all(i["code"] != "repeat_offender" for i in plain_data["indicators"])

    def test_report_escalated_to_high_on_repeat(self, client, make_user):
        account = make_user()
        h = account["headers"]
        sender = "073 444 9922"

        first = client.post(
            "/api/v1/reports",
            json={
                "phishing_type": "WhatsApp or social media message",
                "message": "Congratulations! You have won R50000. Send us a R150 admin fee and it is yours.",
                "risk_level": "high",
                "sender": sender,
            },
            headers=h,
        )
        assert first.status_code == 201

        # Same number again - the reporter even guessed "low", but the system
        # knows better: repetitive scam -> HIGH.
        second = client.post(
            "/api/v1/reports",
            json={
                "phishing_type": "WhatsApp or social media message",
                "message": "They contacted my mother too - same lottery story, R200 admin fee.",
                "risk_level": "low",
                "sender": "+27 73 444 9922",
            },
            headers=h,
        )
        assert second.status_code == 201
        assert second.json()["risk_level"] == "HIGH"
