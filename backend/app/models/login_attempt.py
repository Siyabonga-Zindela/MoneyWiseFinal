"""login_attempts table - brute-force telemetry; raw IPs never stored."""

from datetime import datetime

from sqlalchemy import CHAR, BigInteger, Boolean, DateTime, ForeignKey, Identity, String, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    attempt_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    email_attempted: Mapped[str | None] = mapped_column(String(255))
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    ip_hash: Mapped[str | None] = mapped_column(CHAR(64))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(100))
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
