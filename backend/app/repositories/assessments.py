"""risk_assessments / assessment_evidence data access.

Every /api/v1/analysis call is recorded here: the outcome row plus one
evidence row per fired indicator ("what led to this result"). scam_reports
rows can then reference the assessment via assessment_id.
"""

from decimal import Decimal

from sqlalchemy.orm import Session

from ..models.enums import AssessmentSource, AssessmentType, RiskCategoryDB
from ..models.risk_assessment import AssessmentEvidence, RiskAssessment
from ..services.ai_analysis.schemas import IndicatorSeverity, ScamAssessment

# Weight snapshot stored per evidence row (mirrors the score computation).
SEVERITY_WEIGHTS = {
    IndicatorSeverity.HIGH: Decimal("35.00"),
    IndicatorSeverity.MEDIUM: Decimal("15.00"),
}


def create_assessment(
    db: Session,
    *,
    user_id: int | None,
    input_content: str,
    assessment: ScamAssessment,
    engine_source: AssessmentSource,
    ai_model_name: str | None = None,
    ai_validated: bool | None = None,
    assessment_type: AssessmentType = AssessmentType.SCAM_CONTENT,
) -> RiskAssessment:
    row = RiskAssessment(
        user_id=user_id,
        assessment_type=assessment_type,
        risk_category=RiskCategoryDB[assessment.category.value.upper()],
        risk_score=assessment.risk_score,
        engine_source=engine_source,
        ai_model_name=ai_model_name,
        ai_validated=ai_validated,
        ai_response=assessment.model_dump(mode="json"),
        input_content=input_content,
        summary=assessment.explanation,
        recommended_actions="\n".join(f"- {step}" for step in assessment.next_steps),
        limitations=assessment.limitations,
    )
    db.add(row)
    db.flush()

    for indicator in assessment.indicators:
        db.add(
            AssessmentEvidence(
                assessment_id=row.assessment_id,
                indicator_code_snapshot=indicator.code[:50],
                description=f"{indicator.title}: {indicator.explanation}",
                matched_text=indicator.evidence,
                weight_applied=SEVERITY_WEIGHTS.get(indicator.severity),
                source=engine_source,
            )
        )
    db.flush()
    return row
