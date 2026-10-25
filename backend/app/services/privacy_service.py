"""POPIA privacy flows: request intake, admin processing + account anonymisation, data export."""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..core.deps import get_user_roles
from ..models.enums import AuditAction, PrivacyRequestStatus, PrivacyRequestType
from ..models.user import User
from ..repositories import audit as audit_repo
from ..repositories import privacy as privacy_repo
from ..repositories import reports as reports_repo
from ..repositories import users as users_repo
from ..schemas.privacy import PrivacyProcessRequest, PrivacyRequestCreate


def create_request(
    db: Session,
    user: User,
    payload: PrivacyRequestCreate,
    *,
    ip_hash_value: str | None = None,
):
    request = privacy_repo.create(
        db,
        user_id=user.user_id,
        request_type=payload.request_type,
        details=payload.details,
    )
    audit_repo.write(
        db,
        actor_user_id=user.user_id,
        action=AuditAction.CREATE,
        entity_type="privacy_request",
        entity_id=request.request_id,
        details={"request_type": payload.request_type.value},
        ip_hash=ip_hash_value,
    )
    db.commit()
    db.refresh(request)
    return request


def process_request(
    db: Session,
    admin: User,
    request_id: int,
    payload: PrivacyProcessRequest,
    *,
    ip_hash_value: str | None = None,
):
    request = privacy_repo.get(db, request_id)
    if request is None:
        raise HTTPException(status_code=404, detail="Privacy request not found")

    anonymised = False
    if (
        request.request_type is PrivacyRequestType.ACCOUNT_DELETION
        and payload.status is PrivacyRequestStatus.COMPLETED
        and request.user_id is not None
    ):
        target = users_repo.get(db, request.user_id)
        if target is not None:
            if "ADMIN" in get_user_roles(db, target.user_id):
                raise HTTPException(
                    status_code=409,
                    detail="Admin accounts must be demoted before deletion",
                )
            users_repo.anonymise(db, target)
            anonymised = True

    privacy_repo.apply_status(
        db, request, payload.status, payload.retention_note, processed_by=admin.user_id
    )
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.STATUS_CHANGE,
        entity_type="privacy_request",
        entity_id=request.request_id,
        details={"new_status": payload.status.value, "anonymised_user": anonymised},
        ip_hash=ip_hash_value,
    )
    db.commit()
    db.refresh(request)
    return request


def export_my_data(db: Session, user: User) -> dict:
    """POPIA data portability: everything we hold about this account holder."""
    reports, _total = reports_repo.list_for_user(db, user.user_id, limit=1000, offset=0)
    requests, _total = privacy_repo.list_for_user(db, user.user_id, limit=1000, offset=0)
    audit_repo.write(
        db,
        actor_user_id=user.user_id,
        action=AuditAction.EXPORT,
        entity_type="user",
        entity_id=user.user_id,
    )
    db.commit()
    return {
        "profile": {
            "user_id": user.user_id,
            "email": user.email,
            "full_name": user.full_name,
            "phone": user.phone,
            "status": user.status.value,
            "roles": get_user_roles(db, user.user_id),
            "created_at": user.created_at,
            "last_login_at": user.last_login_at,
        },
        "reports": [
            {
                "report_id": r.report_id,
                "title": r.title,
                "channel": r.channel.value,
                "status": r.status.value,
                "created_at": r.created_at,
            }
            for r in reports
        ],
        "privacy_requests": [
            {
                "request_id": q.request_id,
                "request_type": q.request_type.value,
                "status": q.status.value,
                "requested_at": q.requested_at,
            }
            for q in requests
        ],
    }
