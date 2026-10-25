"""POPIA privacy endpoints: intake, own tracking, admin processing, data export."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..core.deps import client_ip, get_current_user, require_admin
from ..core.security import hash_ip
from ..db.session import get_db
from ..models.enums import PrivacyRequestStatus
from ..models.user import User
from ..repositories import privacy as privacy_repo
from ..schemas.common import Page
from ..schemas.privacy import (
    PrivacyProcessRequest,
    PrivacyRequestCreate,
    PrivacyRequestOut,
)
from ..services import privacy_service

router = APIRouter(prefix="/api/v1/privacy", tags=["privacy"])


@router.post("/requests", response_model=PrivacyRequestOut, status_code=201)
def create_request(
    payload: PrivacyRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Submit a POPIA request (deletion / export / correction / opt-out)."""
    return privacy_service.create_request(
        db, user, payload, ip_hash_value=hash_ip(client_ip(request))
    )


@router.get("/requests", response_model=list[PrivacyRequestOut])
def my_requests(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """My own POPIA requests and their fulfilment status."""
    items, _total = privacy_repo.list_for_user(db, user.user_id, limit=100, offset=0)
    return items


@router.get("/export")
def export_my_data(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """POPIA data portability: everything we hold about this account holder."""
    return privacy_service.export_my_data(db, user)


@router.get("/requests/all", response_model=Page[PrivacyRequestOut])
def all_requests(
    status: PrivacyRequestStatus | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin: the full POPIA fulfilment queue."""
    items, total = privacy_repo.list_all(db, status=status, limit=limit, offset=offset)
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.patch("/requests/{request_id}", response_model=PrivacyRequestOut)
def process_request(
    request_id: int,
    payload: PrivacyProcessRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin: progress a request. COMPLETED account-deletions anonymise the user."""
    return privacy_service.process_request(
        db, admin, request_id, payload, ip_hash_value=hash_ip(client_ip(request))
    )
