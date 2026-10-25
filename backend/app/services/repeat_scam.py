"""Repeat-scam detection from real report history (no new tables, no mocks).

The community-reported scam corpus already lives in scam_reports. This module
turns that history into an evidence-backed signal:

- **Contact match** - the same phone number, email address, website or handle
  was reported before (normalised, so "+27 72 123 4567" matches "0721234567").
- **Provider/organisation match** - the text names an organisation that is
  impersonated across several reports. The organisation registry is the real
  stakeholder_profiles.organisation column (banks/telcos/regulators the admin
  enrolled) - nothing is hard-coded.

The signal only ever ADDS real counts to the deterministic assessment:
a contact with prior reports is escalated to HIGH ("repetitive scam"), and the
OpenRouter AI - which never changes verdicts - is given the counts as trusted
context so its explanation states the history as recorded facts.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .ai_analysis.schemas import (
    AnalysisIndicator,
    IndicatorSeverity,
    RiskCategory,
    ScamAssessment,
)
from ..models.scam_report import ScamReport
from ..models.stakeholder import StakeholderProfile
from ..models.user import User, UserStatus

# A phone key shorter than this would match unrelated short numbers.
_MIN_PHONE_DIGITS = 7
# Organisation names shorter than this are too generic to match on ("AB").
_MIN_ORG_LEN = 3
# How far back "recent" activity is counted for the narrative.
_RECENT_WINDOW = timedelta(days=30)


@dataclass
class RepeatSignal:
    """What the report history says about this sender/provider."""

    prior_contact_reports: int = 0
    prior_org_reports: int = 0
    recent_contact_reports: int = 0
    prior_report_ids: list[int] = field(default_factory=list)
    prior_dates: list[str] = field(default_factory=list)
    matched_label: str | None = None  # e.g. "number 072 123 4567"

    @property
    def total_priors(self) -> int:
        # Contact and organisation matches can overlap; the sum is the honest
        # "how many earlier reports point the same way" figure we display.
        return self.prior_contact_reports + self.prior_org_reports

    @property
    def is_repeat(self) -> bool:
        return self.total_priors > 0

    def to_prompt_context(self) -> dict | None:
        """Trusted context for the AI explanation (None when nothing to add)."""
        if not self.is_repeat:
            return None
        return {
            "prior_reports_matching_this_sender": self.prior_contact_reports,
            "prior_reports_naming_the_same_provider": self.prior_org_reports,
            "in_the_last_30_days": self.recent_contact_reports,
            "matched": self.matched_label,
            "earliest_prior_report_date": self.prior_dates[-1] if self.prior_dates else None,
            "note": (
                "Counts come from the MoneyWise report database and are facts. "
                "Mention them plainly in the explanation; do not invent further history."
            ),
        }


def contact_keys(contact: str | None) -> list[str]:
    """Normalise a sender identifier into comparable match keys.

    - phone: digits only; the last 9 digits make +27 72 123 4567 and
      0721234567 the same number (SA numbers are 9 digits locally).
    - email / handle: lowercase, trimmed.
    - URL: bare hostname, lowercase ("https://fnb-win.co.za/x" -> fnb-win.co.za).
    """
    if not contact:
        return []
    value = contact.strip()
    if not value:
        return []

    keys: list[str] = []
    lowered = value.lower()

    # Email (contains @ with something on both sides).
    if "@" in lowered and not lowered.startswith("@") and not lowered.endswith("@"):
        local, _, domain = lowered.partition("@")
        keys.append(lowered)
        # A WhatsApp/SMS "sender" may share the domain across spoofed local
        # parts - the bare domain is the provider-level key.
        if "." in domain:
            keys.append(f"url:{domain}")
    else:
        digits = re.sub(r"\D", "", value)
        if len(digits) >= _MIN_PHONE_DIGITS:
            # Last 9 digits absorb country codes (+27...) and leading zeros.
            keys.append(digits[-9:] if len(digits) >= 9 else digits)
        # Web/link senders: extract the hostname.
        if "." in lowered and "/" in lowered or lowered.startswith(("http", "www.")):
            host = _hostname(value)
            if host:
                keys.append(f"url:{host}")
        elif "." in lowered and " " not in lowered and digits == "":
            # Bare domain typed as the sender (e.g. "fnb-winner.co.za").
            host = lowered.removeprefix("www.")
            if host:
                keys.append(f"url:{host}")
        if not keys and len(lowered) >= 3:
            # Handle / username.
            keys.append(lowered)
    # Deduplicate, keep order.
    seen: set[str] = set()
    return [k for k in keys if not (k in seen or seen.add(k))]


def _hostname(value: str) -> str | None:
    candidate = value.strip().lower()
    candidate = re.sub(r"^[a-z][a-z0-9+.-]*://", "", candidate)  # scheme
    candidate = candidate.removeprefix("www.")
    host = candidate.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1]  # drop user@
    host = host.split(":")[0]  # drop port
    if "." in host and re.fullmatch(r"[a-z0-9.-]+", host):
        return host
    return None


def organisation_keys(text: str | None) -> list[str]:
    """Organisation names (from the stakeholder registry) present in the text."""
    return _orgs_in_text(text)


def _org_registry(db: Session) -> list[str]:
    """Active stakeholders' organisation names, longest first."""
    rows = db.execute(
        select(StakeholderProfile.organisation)
        .join(User, User.user_id == StakeholderProfile.user_id)
        .where(User.status != UserStatus.DELETED)
    ).scalars().all()
    names = {org.strip() for org in rows if org and len(org.strip()) >= _MIN_ORG_LEN}
    return sorted(names, key=len, reverse=True)


def _orgs_in_text(text: str | None, registry: list[str] | None = None) -> list[str]:
    if not text:
        return []
    if registry is None:
        return []
    haystack = text.casefold()
    hits: list[str] = []
    for org in registry:
        needle = org.casefold()
        if re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", haystack):
            hits.append(org)
    return hits


def _priors_query(db: Session, keys: list[str], exclude_report_id: int | None):
    """scam_reports whose reported_contact matches any key."""
    if not keys:
        return None
    conditions = []
    for key in keys:
        if key.startswith("url:"):
            conditions.append(func.lower(ScamReport.reported_contact).like(f"%{key[4:]}%"))
        elif key.isdigit():
            digits_expr = func.regexp_replace(ScamReport.reported_contact, r"\D", "", "g")
            conditions.append(digits_expr.endswith(key))
        else:
            conditions.append(func.lower(ScamReport.reported_contact) == key)
    query = select(ScamReport).where(or_(*conditions))
    if exclude_report_id is not None:
        query = query.where(ScamReport.report_id != exclude_report_id)
    return query


def _org_priors_query(db: Session, orgs: list[str], exclude_report_id: int | None):
    """scam_reports whose text names one of the given organisations."""
    if not orgs:
        return None
    conditions = [
        or_(
            ScamReport.description.ilike(f"%{org}%"),
            ScamReport.title.ilike(f"%{org}%"),
            ScamReport.phishing_type.ilike(f"%{org}%"),
        )
        for org in orgs
    ]
    query = select(ScamReport).where(or_(*conditions))
    if exclude_report_id is not None:
        query = query.where(ScamReport.report_id != exclude_report_id)
    return query


def signal_for(
    db: Session,
    *,
    contact: str | None = None,
    text: str | None = None,
    exclude_report_id: int | None = None,
) -> RepeatSignal:
    """Look up the report history for this sender / provider (read-only)."""
    signal = RepeatSignal()
    registry = _org_registry(db)
    since = datetime.now(timezone.utc) - _RECENT_WINDOW

    keys = contact_keys(contact)
    if keys:
        query = _priors_query(db, keys, exclude_report_id)
        if query is not None:
            rows = db.scalars(query.order_by(ScamReport.report_id.asc()).limit(200)).all()
            signal.prior_contact_reports = len(rows)
            signal.recent_contact_reports = sum(
                1 for r in rows if r.created_at and r.created_at >= since
            )
            signal.prior_report_ids = [r.report_id for r in rows[:10]]
            signal.prior_dates = [
                (r.occurred_at or r.created_at).date().isoformat()
                for r in rows[:10] if (r.occurred_at or r.created_at)
            ]
            if rows:
                signal.matched_label = _label_for(contact)

    orgs = _orgs_in_text(text, registry) if (text or contact) else []
    # The sender identifier itself can carry the provider name ("FNB alert").
    if contact:
        orgs.extend(o for o in _orgs_in_text(contact, registry) if o not in orgs)
    if orgs:
        query = _org_priors_query(db, orgs, exclude_report_id)
        if query is not None:
            org_rows = db.scalars(query.order_by(ScamReport.report_id.asc()).limit(200)).all()
            matched_ids = set(signal.prior_report_ids)
            fresh = [r for r in org_rows if r.report_id not in matched_ids]
            signal.prior_org_reports = len(fresh)
            signal.prior_report_ids.extend(r.report_id for r in fresh[:10])
            signal.prior_dates.extend(
                (r.occurred_at or r.created_at).date().isoformat()
                for r in fresh[:10] if (r.occurred_at or r.created_at)
            )
            if fresh and signal.matched_label is None:
                signal.matched_label = "provider " + " / ".join(orgs[:2])
            elif fresh:
                signal.matched_label = (signal.matched_label or "") + " + provider " + " / ".join(orgs[:2])

    signal.prior_dates.sort()
    return signal


def _label_for(contact: str | None) -> str:
    if not contact:
        return "sender"
    if "@" in contact:
        return f"address {contact.strip()[:60]}"
    digits = re.sub(r"\D", "", contact)
    if digits and len(digits) >= _MIN_PHONE_DIGITS:
        return f"number {digits[-10:]}"
    return f"sender {contact.strip()[:60]}"


def repeat_counts_for_reports(db: Session, reports: list[ScamReport]) -> dict[int, int]:
    """Bulk repeat counts for the admin dashboard (one query, Python counting)."""
    if not reports:
        return {}
    rows = db.execute(
        select(
            ScamReport.report_id,
            ScamReport.reported_contact,
            ScamReport.description,
            ScamReport.title,
            ScamReport.phishing_type,
        ).order_by(ScamReport.report_id.asc()).limit(1000)
    ).all()
    registry = _org_registry(db)

    contact_map: dict[str, set[int]] = {}
    org_map: dict[str, set[int]] = {}
    for report_id, contact, description, title, phishing_type in rows:
        blob = " ".join(x for x in (description, title, phishing_type) if x)
        for key in contact_keys(contact):
            contact_map.setdefault(key, set()).add(report_id)
        for org in _orgs_in_text(blob, registry):
            org_map.setdefault(org.casefold(), set()).add(report_id)

    counts: dict[int, int] = {}
    wanted = {r.report_id for r in reports}
    for report_id, contact, description, title, phishing_type in rows:
        if report_id not in wanted:
            continue
        blob = " ".join(x for x in (description, title, phishing_type) if x)
        others: set[int] = set()
        for key in contact_keys(contact):
            others |= contact_map.get(key, set())
        for org in _orgs_in_text(blob, registry):
            others |= org_map.get(org.casefold(), set())
        others.discard(report_id)
        counts[report_id] = len(others)
    return counts


def apply_repeat_signal(assessment: ScamAssessment, signal: RepeatSignal) -> ScamAssessment:
    """Escalate the deterministic assessment with real report-history counts.

    Evidence rules (all counts come from scam_reports rows, never invented):
    - 1+ prior report about the SAME contact  -> HIGH (repetitive scam).
    - 2+ prior reports naming the same provider -> HIGH; a single provider
      mention is weaker and only lifts the result to MEDIUM.
    - Score floors: 85 (single contact match), 90 (contact + provider or
      several contact matches), 95 (3+ matches) - "very high risk".
    The verdict is still decided deterministically BEFORE the AI is involved;
    the AI only repeats these recorded counts in its own wording.
    """
    if not signal.is_repeat:
        return assessment

    priors = signal.total_priors
    contact_repeat = signal.prior_contact_reports >= 1
    strong = contact_repeat or signal.prior_org_reports >= 2

    if strong:
        category = RiskCategory.HIGH
        if priors >= 3:
            floor = 95.0
        elif signal.prior_contact_reports >= 2 or (
            contact_repeat and signal.prior_org_reports >= 1
        ):
            floor = 90.0
        else:
            floor = 85.0
    else:  # a single provider-name mention only
        category = RiskCategory.MEDIUM
        floor = 50.0

    severity = IndicatorSeverity.HIGH if strong else IndicatorSeverity.MEDIUM
    times = "time" if priors == 1 else "times"
    history = (
        f"MoneyWise users have already reported this {signal.matched_label or 'sender'} "
        f"{priors} {times}"
    )
    if signal.recent_contact_reports:
        history += (
            f" - {signal.recent_contact_reports} of those reports came in the last 30 days"
        )
    history += (
        ". The same sender or provider reaching more people is a strong sign of an "
        "active scam campaign, so this check is treated as high risk."
        if strong
        else ". Other people have reported the same provider before, which raises the risk."
    )

    indicator = AnalysisIndicator(
        code="repeat_offender",
        title=f"Reported {priors} {times} before",
        explanation=history,
        evidence=(
            f"{priors} earlier report(s) match this "
            f"{signal.matched_label or 'sender'}"
        ),
        context=None,
        severity=severity,
    )

    indicators = [indicator, *assessment.indicators]
    raw = min(
        sum(35.0 if ind.severity == IndicatorSeverity.HIGH else 15.0 for ind in indicators),
        90.0,
    )
    # Never lower a score the baseline already earned (e.g. HIGH at 100).
    previous = assessment.risk_score if assessment.category == category else 0.0
    if category == RiskCategory.HIGH:
        score = round(max(previous, 80.0, raw, floor), 1)
    elif category == RiskCategory.MEDIUM:
        score = round(max(previous, 50.0, raw, floor), 1)
    else:
        score = 0.0

    return assessment.model_copy(
        update={"category": category, "risk_score": score, "indicators": indicators}
    )
