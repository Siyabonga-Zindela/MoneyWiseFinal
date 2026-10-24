"""Admin audit trail - append-only and read-only through this API."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..core.deps import require_admin
from ..db.session import get_db
from ..models.enums import AuditAction
from ..models.user import User
from ..repositories import audit as audit_repo
from ..schemas.audit import AuditOut
from ..schemas.common import Page

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("", response_model=Page[AuditOut])
def list_audit(
    action: AuditAction | None = Query(default=None),
    entity_type: str | None = Query(default=None, max_length=100),
    actor_user_id: int | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin-only. Filter by action, entity or actor; newest first."""
    items, total = audit_repo.list_all(
        db,
        action=action,
        entity_type=entity_type,
        actor_user_id=actor_user_id,
        limit=limit,
        offset=offset,
    )
    return Page(items=items, total=total, limit=limit, offset=offset)
