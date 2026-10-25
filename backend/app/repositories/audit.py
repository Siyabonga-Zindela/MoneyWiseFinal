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


# ---- report forwarding (no new tables: recorded in the append-only trail) ----

SEND_ENTITY = "stakeholder_report_send"
ACK_ENTITY = "stakeholder_report_ack"


def sends_for_stakeholder(db: Session, stakeholder_user_id: int) -> list[AuditLog]:
    """Every forward addressed to one stakeholder, oldest first."""
    return list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.entity_type == SEND_ENTITY, AuditLog.entity_id == stakeholder_user_id)
            .order_by(AuditLog.created_at.asc(), AuditLog.audit_id.asc())
            .limit(500)
        ).all()
    )


def sends_for_reports(db: Session, report_ids: list[int]) -> list[AuditLog]:
    """All forwards for the given reports (details->>report_id)."""
    if not report_ids:
        return []
    id_texts = [str(rid) for rid in report_ids]
    return list(
        db.scalars(
            select(AuditLog)
            .where(
                AuditLog.entity_type == SEND_ENTITY,
                AuditLog.details.op("->>")("report_id").in_(id_texts),
            )
            .order_by(AuditLog.created_at.asc(), AuditLog.audit_id.asc())
        ).all()
    )


def acks_for_reports(db: Session, report_ids: list[int]) -> list[AuditLog]:
    """Stakeholder acknowledgements for the given reports, newest first."""
    if not report_ids:
        return []
    return list(
        db.scalars(
            select(AuditLog)
            .where(
                AuditLog.entity_type == ACK_ENTITY,
                AuditLog.entity_id.in_(report_ids),
            )
            .order_by(AuditLog.created_at.desc(), AuditLog.audit_id.desc())
        ).all()
    )
