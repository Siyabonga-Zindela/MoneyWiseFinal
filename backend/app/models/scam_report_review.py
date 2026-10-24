"""scam_report_reviews table - one row per admin decision; append-only by convention."""

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Identity, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base
from .enums import ReviewAction, pg_enum


class ScamReportReview(Base):
    __tablename__ = "scam_report_reviews"

    review_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    report_id: Mapped[int] = mapped_column(
        ForeignKey("scam_reports.report_id", ondelete="CASCADE"), nullable=False
    )
    reviewer_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    action: Mapped[ReviewAction] = mapped_column(
        pg_enum(ReviewAction, "review_action"), nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
