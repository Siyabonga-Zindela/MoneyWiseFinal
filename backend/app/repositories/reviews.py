"""scam_report_reviews data access - append-only decision trail."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.enums import ReviewAction
from ..models.scam_report_review import ScamReportReview


def create(
    db: Session,
    *,
    report_id: int,
    reviewer_id: int,
    action: ReviewAction,
    notes: str | None = None,
) -> ScamReportReview:
    review = ScamReportReview(
        report_id=report_id,
        reviewer_id=reviewer_id,
        action=action,
        notes=notes,
    )
    db.add(review)
    db.flush()
    return review


def list_for_report(db: Session, report_id: int) -> list[ScamReportReview]:
    return list(
        db.scalars(
            select(ScamReportReview)
            .where(ScamReportReview.report_id == report_id)
            .order_by(ScamReportReview.decided_at.desc(), ScamReportReview.review_id.desc())
        ).all()
    )
