"""Stakeholder tables (migration 0003) - external partner accounts + offers.

stakeholder_profiles carries the org metadata the admin-users screen manages;
auth/lockout stays on users (reused, not duplicated). stakeholder_offers are
the investment offers a partner lists - column names mirror the
externalStakeholder UI form fields exactly.
"""

from datetime import datetime
from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Identity, Numeric, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base


class StakeholderProfile(Base):
    __tablename__ = "stakeholder_profiles"

    stakeholder_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, unique=True
    )
    organisation: Mapped[str] = mapped_column(String(150), nullable=False)
    org_type: Mapped[str] = mapped_column(String(20), nullable=False)
    access: Mapped[str] = mapped_column(String(10), nullable=False, server_default="view")
    alerts: Mapped[str] = mapped_column(String(10), nullable=False, server_default="none")
    invite_pending: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class StakeholderOffer(Base):
    __tablename__ = "stakeholder_offers"

    offer_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    product_name: Mapped[str] = mapped_column(String(150), nullable=False)
    product_category: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    currency: Mapped[str] = mapped_column(String(8), nullable=False, server_default="ZAR")
    min_investment: Mapped[Decimal] = mapped_column(Numeric(14, 2), nullable=False)
    max_investment: Mapped[Decimal] = mapped_column(Numeric(14, 2), nullable=False)
    fees_summary: Mapped[str | None] = mapped_column(Text)
    indicative_return_range: Mapped[str | None] = mapped_column(String(120))
    access_condition: Mapped[str | None] = mapped_column(String(300))
    material_risk: Mapped[str | None] = mapped_column(Text)
    suitable_timeframe: Mapped[str | None] = mapped_column(String(120))
    url: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
