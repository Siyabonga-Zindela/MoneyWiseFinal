"""user_privacy_requests table - POPIA rights fulfilment trail."""

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Identity, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base
from .enums import PrivacyRequestStatus, PrivacyRequestType, pg_enum


class PrivacyRequest(Base):
    __tablename__ = "user_privacy_requests"

    request_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    request_type: Mapped[PrivacyRequestType] = mapped_column(
        pg_enum(PrivacyRequestType, "privacy_request_type"), nullable=False
    )
    status: Mapped[PrivacyRequestStatus] = mapped_column(
        pg_enum(PrivacyRequestStatus, "privacy_request_status"),
        nullable=False,
        server_default=text("'RECEIVED'"),
    )
    details: Mapped[str | None] = mapped_column(Text)
    retention_note: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    processed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
