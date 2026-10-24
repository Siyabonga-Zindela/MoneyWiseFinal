"""Audit trail response shapes (append-only; admin read-only access)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from ..models.enums import AuditAction


class AuditOut(BaseModel):
    audit_id: int
    actor_user_id: int | None = None
    action: AuditAction
    entity_type: str
    entity_id: int | None = None
    details: dict[str, Any] | None = None
    ip_hash: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
