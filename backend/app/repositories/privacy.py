"""user_privacy_requests data access (POPIA rights fulfilment)."""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.enums import PrivacyRequestStatus, PrivacyRequestType
from ..models.privacy_request import PrivacyRequest


def get(db: Session, request_id: int) -> PrivacyRequest | None:
    return db.get(PrivacyRequest, request_id)


def create(
    db: Session,
    *,
    user_id: int,
    request_type: PrivacyRequestType,
    details: str | None = None,
) -> PrivacyRequest:
    request = PrivacyRequest(user_id=user_id, request_type=request_type, details=details)
    db.add(request)
    db.flush()
    return request


def list_for_user(
    db: Session, user_id: int, limit: int = 50, offset: int = 0
) -> tuple[list[PrivacyRequest], int]:
    base = select(PrivacyRequest).where(PrivacyRequest.user_id == user_id)
    return _run_page(db, base, limit, offset)


def list_all(
    db: Session,
    status: PrivacyRequestStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[PrivacyRequest], int]:
    base = select(PrivacyRequest)
    if status is not None:
        base = base.where(PrivacyRequest.status == status)
    return _run_page(db, base, limit, offset)


def apply_status(
    db: Session,
    request: PrivacyRequest,
    status: PrivacyRequestStatus,
    retention_note: str | None,
    processed_by: int,
) -> None:
    terminal = status in (
        PrivacyRequestStatus.COMPLETED,
        PrivacyRequestStatus.PARTIALLY_COMPLETED,
        PrivacyRequestStatus.REJECTED,
    )
    request.status = status
    request.completed_at = datetime.now(timezone.utc) if terminal else None
    request.retention_note = retention_note
    request.processed_by = processed_by
    db.flush()


def _run_page(db: Session, base, limit: int, offset: int):
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    items = list(
        db.scalars(
            base.order_by(PrivacyRequest.requested_at.desc(), PrivacyRequest.request_id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return items, total
