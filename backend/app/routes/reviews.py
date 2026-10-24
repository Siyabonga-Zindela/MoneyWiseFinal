"""Admin review endpoints - one decision = one append-only review row."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.deps import client_ip, require_admin
from ..core.security import hash_ip
from ..db.session import get_db
from ..models.scam_report_review import ScamReportReview
from ..models.user import User
from ..schemas.review import ReviewCreate, ReviewOut
from ..services import report_service

router = APIRouter(prefix="/api/v1", tags=["reviews"])


@router.post("/reports/{report_id}/reviews", response_model=ReviewOut, status_code=201)
def review_report(
    report_id: int,
    payload: ReviewCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> ScamReportReview:
    """Record an admin decision (APPROVED / REJECTED / REQUIRES_INVESTIGATION)
    and transition the report status. History is append-only."""
    _report, review = report_service.review_report(
        db, admin, report_id, payload, ip_hash_value=hash_ip(client_ip(request))
    )
    return review
