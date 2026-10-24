"""user_roles junction - authorisation is enforced in the BACKEND from this mapping."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.role_id", ondelete="RESTRICT"), primary_key=True
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    assigned_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
