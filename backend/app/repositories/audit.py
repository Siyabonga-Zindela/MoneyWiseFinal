"""audit_logs data access - append-only: write() and read; never update/delete."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.audit_log import AuditLog
from ..models.enums import AuditAction


def write(
    db: Session,
    *,
    actor_user_id: int | None,
    action: AuditAction,
    entity_type: str,
    entity_id: int | None = None,
    details: dict | None = None,
    ip_hash: str | None = None,
) -> None:
    db.add(
        AuditLog(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            ip_hash=ip_hash,
        )
    )
    db.flush()


def list_all(
    db: Session,
    *,
    action: AuditAction | None = None,
    entity_type: str | None = None,
    actor_user_id: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuditLog], int]:
    base = select(AuditLog)
    if action is not None:
        base = base.where(AuditLog.action == action)
    if entity_type is not None:
        base = base.where(AuditLog.entity_type == entity_type)
    if actor_user_id is not None:
        base = base.where(AuditLog.actor_user_id == actor_user_id)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    items = list(
        db.scalars(
            base.order_by(AuditLog.created_at.desc(), AuditLog.audit_id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return items, total
