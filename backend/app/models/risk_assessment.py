"""risk_assessments + assessment_evidence tables.

Every analysis (rule engine and/or AI) is persisted here so the "what led to
this result" trail survives: the assessment row stores the outcome, and one
evidence row per fired indicator keeps the exact matched text. Reports can
reference an assessment via scam_reports.assessment_id.
"""

from datetime import datetime
from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Identity, Numeric, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base
from .enums import AssessmentSource, AssessmentType, RiskCategoryDB, pg_enum


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    assessment_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    assessment_type: Mapped[AssessmentType] = mapped_column(
        pg_enum(AssessmentType, "assessment_type"), nullable=False
    )
    risk_category: Mapped[RiskCategoryDB] = mapped_column(
        pg_enum(RiskCategoryDB, "risk_category"), nullable=False
    )
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    engine_source: Mapped[AssessmentSource] = mapped_column(
        pg_enum(AssessmentSource, "assessment_source"),
        nullable=False,
        server_default=text("'BASELINE_ENGINE'"),
    )
    ai_model_name: Mapped[str | None] = mapped_column(String(120))
    ai_validated: Mapped[bool | None] = mapped_column(Boolean)
    ai_response: Mapped[dict | None] = mapped_column(JSONB)
    input_content: Mapped[str] = mapped_column(Text, nullable=False)
    input_url: Mapped[str | None] = mapped_column(String(2048))
    input_amount: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_actions: Mapped[str | None] = mapped_column(Text)
    limitations: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AssessmentEvidence(Base):
    __tablename__ = "assessment_evidence"

    evidence_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("risk_assessments.assessment_id", ondelete="CASCADE"), nullable=False
    )
    indicator_id: Mapped[int | None] = mapped_column(BigInteger)
    indicator_code_snapshot: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    matched_text: Mapped[str | None] = mapped_column(Text)
    weight_applied: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    source: Mapped[AssessmentSource] = mapped_column(
        pg_enum(AssessmentSource, "assessment_source"),
        nullable=False,
        server_default=text("'BASELINE_ENGINE'"),
    )
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
