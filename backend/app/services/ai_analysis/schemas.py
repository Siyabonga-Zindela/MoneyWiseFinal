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

    @field_validator("text", mode="before")
    @classmethod
    def strip_text(cls, value: str) -> str:
        if isinstance(value, str):
            return value.strip()
        return value


class AnalysisIndicator(BaseModel):
    code: str
    title: str
    explanation: str
    evidence: str
    severity: IndicatorSeverity


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
