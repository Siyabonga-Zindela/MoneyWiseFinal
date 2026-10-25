"""Scam report business logic: duplicate linking + admin review transitions."""

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..core.security import sha256_hex
from ..models.enums import AuditAction, ReportStatus, RiskCategoryDB, ScamChannel
from ..models.scam_report import ScamReport
from ..models.scam_report_review import ScamReportReview
from ..models.user import User
from ..repositories import audit as audit_repo
from ..repositories import reports as reports_repo
from ..repositories import reviews as reviews_repo
from ..schemas.report import ReportCreate, VisibilityUpdate
from ..schemas.review import ReviewCreate
from .repeat_scam import signal_for


def content_hash_for(title: str, description: str) -> str:
    """SHA-256 of normalised content - whitespace/case insensitive duplicate detection."""
    normalised_title = " ".join(title.lower().split())
    normalised_body = " ".join(description.lower().split())
    return sha256_hex(f"{normalised_title}|{normalised_body}")


def create_report(
    db: Session,
    reporter: User | None,
    payload: ReportCreate,
    *,
    ip_hash_value: str | None = None,
    screenshot_path: str | None = None,
) -> ScamReport:
    content_hash = content_hash_for(payload.title, payload.description)
    original = reports_repo.find_original_by_hash(db, content_hash)
    report = reports_repo.create(
        db,
        reporter_id=reporter.user_id if reporter else None,
        payload=payload,
        content_hash=content_hash,
        duplicate_of_id=original.report_id if original else None,
        screenshot_path=screenshot_path,
    )

    # Repetitive-scam flag: real history against the SAME contact/provider.
    # A sender or provider that has been reported before is escalated to HIGH
    # regardless of the reporter's own guess - the counts are recorded facts
    # and travel with the report into the admin dashboard.
    try:
        repeat = signal_for(
            db,
            contact=payload.reported_contact,
            text=f"{payload.title} {payload.description}",
            exclude_report_id=report.report_id,
        )
    except Exception:
        # History lookup is read-only and must never block a report from
        # being filed; without it we simply record no repeat signal.
        repeat = None
    escalated = False
    if (
        repeat is not None
        and repeat.is_repeat
        and report.risk_level is not RiskCategoryDB.HIGH
    ):
        report.risk_level = RiskCategoryDB.HIGH
        escalated = True

    audit_repo.write(
        db,
        actor_user_id=reporter.user_id if reporter else None,
        action=AuditAction.CREATE,
        entity_type="scam_report",
        entity_id=report.report_id,
        details={
            "channel": (payload.channel or ScamChannel.OTHER).value,
            "phishing_type": payload.phishing_type,
            "risk_level": payload.risk_level,
            "duplicate": original is not None,
            "screenshot": screenshot_path is not None,
            "repeat_signal": {
                "escalated": escalated,
                "prior_contact_reports": repeat.prior_contact_reports,
                "prior_org_reports": repeat.prior_org_reports,
            }
            if (repeat is not None and repeat.is_repeat)
            else None,
        },
        ip_hash=ip_hash_value,
    )
    db.commit()
    db.refresh(report)
    return report


def review_report(
    db: Session,
    admin: User,
    report_id: int,
    payload: ReviewCreate,
    *,
    ip_hash_value: str | None = None,
) -> tuple[ScamReport, ScamReportReview]:
    report = reports_repo.get(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status in (ReportStatus.APPROVED, ReportStatus.REJECTED):
        raise HTTPException(
            status_code=409,
            detail="A final decision was already recorded for this report",
        )

    review = reviews_repo.create(
        db,
        report_id=report.report_id,
        reviewer_id=admin.user_id,
        action=payload.action,
        notes=payload.notes,
    )
    # review_action and report_status share labels, so the decision maps 1:1.
    reports_repo.set_status(db, report, ReportStatus(payload.action.value))
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.STATUS_CHANGE,
        entity_type="scam_report",
        entity_id=report.report_id,
        details={"decision": payload.action.value},
        ip_hash=ip_hash_value,
    )
    db.commit()
    db.refresh(report)
    db.refresh(review)
    return report, review


def set_visibility(
    db: Session,
    admin: User,
    report: ScamReport,
    payload: VisibilityUpdate,
    *,
    ip_hash_value: str | None = None,
) -> ScamReport:
    reports_repo.set_public(db, report, payload.is_public)
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.UPDATE,
        entity_type="scam_report",
        entity_id=report.report_id,
        details={"is_public": payload.is_public},
        ip_hash=ip_hash_value,
    )
    db.commit()
    db.refresh(report)
    return report
