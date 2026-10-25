"""Data shapes used by the scam analysis service."""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


class RiskCategory(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    INCONCLUSIVE = "inconclusive"


class IndicatorSeverity(str, Enum):
    MEDIUM = "medium"
    HIGH = "high"


class ScamAnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    # Optional sender identifier (phone / email / link). When given, the
    # engine also checks the report history for this contact and escalates
    # the verdict if the same sender has been reported before. Purely
    # additive: omitting it keeps the request byte-for-byte compatible.
    sender: str | None = Field(default=None, max_length=255)

    @field_validator("text", mode="before")
    @classmethod
    def strip_text(cls, value: str) -> str:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("sender", mode="before")
    @classmethod
    def strip_sender(cls, value: str | None) -> str | None:
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value


class AnalysisIndicator(BaseModel):
    code: str
    title: str
    explanation: str
    evidence: str
    severity: IndicatorSeverity
    # Quote of the matched phrase WITH its surrounding words, cut from the
    # original message, so the user can see exactly where it appears.
    context: str | None = None


class ScamAssessment(BaseModel):
    assessment_id: int | None = Field(
        default=None,
        description="risk_assessments row id - present once the analysis is saved",
    )
    category: RiskCategory
    risk_score: float = Field(
        default=0.0, ge=0, le=100,
        description="0-100 pyramid-scam likelihood shown to the user",
    )
    indicators: list[AnalysisIndicator] = Field(default_factory=list)
    explanation: str
    next_steps: list[str]
    limitations: str
    # How the user can independently verify the offer/sender via trusted
    # channels. Deterministic (derived from the category), never AI-invented.
    verification: str = ""
    source: str = "deterministic_rules"


def compute_risk_score(category: RiskCategory, indicators: list[AnalysisIndicator]) -> float:
    """Deterministic 0-100 score: indicator weights, floored by category.

    HIGH-severity indicator weighs 35, MEDIUM 15; the raw sum is capped at 90
    and the category guarantees a floor (HIGH >= 80, MEDIUM >= 50, LOW <= 25)
    so the number always agrees with the verdict the user is shown.
    """
    raw = 0.0
    for indicator in indicators:
        raw += 35.0 if indicator.severity == IndicatorSeverity.HIGH else 15.0
    raw = min(raw, 90.0)

    if category == RiskCategory.HIGH:
        return round(max(80.0, raw), 1)
    if category == RiskCategory.MEDIUM:
        return round(max(50.0, raw), 1)
    if category == RiskCategory.LOW:
        return round(min(raw, 25.0), 1)
    return 0.0  # INCONCLUSIVE


class AIAnalysisExplanation(BaseModel):
    explanation: str = Field(min_length=1, max_length=1200)
    next_steps: list[Annotated[str, Field(min_length=1, max_length=300)]] = Field(
        min_length=1, max_length=5
    )
    limitations: str = Field(min_length=1, max_length=800)
