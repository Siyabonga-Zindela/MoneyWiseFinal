"""scam_reports table - duplicates are LINKED via duplicate_of_id, never merged.

Aligned with the frontend report popup (migration 0002): the popup collects
phishing_type, message, risk_level, date_received, sender, amount_asked,
amount_promised and an optional screenshot.
"""

from datetime import datetime
from decimal import Decimal

from sqlalchemy import CHAR, BigInteger, Boolean, DateTime, ForeignKey, Identity, Numeric, String, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base
from .enums import ReportStatus, RiskCategoryDB, ScamChannel, pg_enum


class ScamReport(Base):
    __tablename__ = "scam_reports"

    report_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    reporter_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    assessment_id: Mapped[int | None] = mapped_column(
        ForeignKey("risk_assessments.assessment_id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    channel: Mapped[ScamChannel] = mapped_column(
        pg_enum(ScamChannel, "scam_channel"),
        nullable=False,
        server_default=text("'OTHER'"),
    )
    reported_url: Mapped[str | None] = mapped_column(String(2048))
    reported_contact: Mapped[str | None] = mapped_column(String(255))
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # --- UI report-popup fields (migration 0002) --------------------------------
    phishing_type: Mapped[str | None] = mapped_column(String(120))
    risk_level: Mapped[RiskCategoryDB | None] = mapped_column(
        pg_enum(RiskCategoryDB, "risk_category")
    )
    amount_asked: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    amount_promised: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    screenshot_path: Mapped[str | None] = mapped_column(String(500))
    # -----------------------------------------------------------------------------
    content_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    duplicate_of_id: Mapped[int | None] = mapped_column(
        ForeignKey("scam_reports.report_id", ondelete="SET NULL")
    )
    status: Mapped[ReportStatus] = mapped_column(
        pg_enum(ReportStatus, "report_status"),
        nullable=False,
        server_default=text("'SUBMITTED'"),
    )
    is_public: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
