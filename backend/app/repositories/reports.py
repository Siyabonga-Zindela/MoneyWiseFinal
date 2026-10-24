"""scam_reports data access."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.enums import ReportStatus, ScamChannel
from ..models.scam_report import ScamReport
from ..schemas.report import ReportCreate


def get(db: Session, report_id: int) -> ScamReport | None:
    return db.get(ScamReport, report_id)


def create(
    db: Session,
    *,
    reporter_id: int,
    payload: ReportCreate,
    content_hash: str,
    duplicate_of_id: int | None = None,
    screenshot_path: str | None = None,
) -> ScamReport:
    report = ScamReport(
        reporter_id=reporter_id,
        assessment_id=payload.assessment_id,
        title=payload.title.strip(),
        description=payload.description.strip(),
        channel=payload.channel or ScamChannel.OTHER,
        reported_url=payload.reported_url,
        reported_contact=payload.reported_contact,
        occurred_at=payload.occurred_at,
        phishing_type=payload.phishing_type,
        risk_level=payload.risk_level_db,
        amount_asked=payload.amount_asked,
        amount_promised=payload.amount_promised,
        screenshot_path=screenshot_path,
        content_hash=content_hash,
        duplicate_of_id=duplicate_of_id,
    )
    db.add(report)
    db.flush()
    return report


def find_original_by_hash(db: Session, content_hash: str) -> ScamReport | None:
    """Oldest report with identical content - duplicates link to it (never merge)."""
    return db.scalar(
        select(ScamReport)
        .where(ScamReport.content_hash == content_hash)
        .order_by(ScamReport.report_id.asc())
        .limit(1)
    )


def list_for_user(
    db: Session, reporter_id: int, limit: int, offset: int
) -> tuple[list[ScamReport], int]:
    base = select(ScamReport).where(ScamReport.reporter_id == reporter_id)
    return _run_page(db, base, limit, offset)


def list_all(
    db: Session,
    status: ReportStatus | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[ScamReport], int]:
    base = select(ScamReport)
    if status is not None:
        base = base.where(ScamReport.status == status)
    return _run_page(db, base, limit, offset)


def set_status(db: Session, report: ScamReport, status: ReportStatus) -> None:
    report.status = status
    db.flush()


def set_public(db: Session, report: ScamReport, is_public: bool) -> None:
    report.is_public = is_public
    db.flush()


def _run_page(
    db: Session, base, limit: int, offset: int
) -> tuple[list[ScamReport], int]:
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    items = list(
        db.scalars(
            base.order_by(ScamReport.created_at.desc(), ScamReport.report_id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return items, total
