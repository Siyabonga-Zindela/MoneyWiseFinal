"""HTTP endpoints for text analysis.

The AI (OpenRouter, with the deterministic rule engine as the always-on
fallback) analyses the submitted text and returns the verdict plus WHAT LED
TO IT: the fired indicators (with the exact matched text), the explanation,
next steps and a 0-100 risk score. Every call is persisted to
risk_assessments + assessment_evidence so reports can reference it and the
explainability trail survives (§6).
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.deps import get_optional_user
from ..core.rate_limit import limiter
from ..db.session import get_db
from ..models.enums import AssessmentSource
from ..models.user import User
from ..repositories import assessments as assessments_repo
from ..services.ai_analysis.openrouter_client import OpenRouterConfig
from ..services.ai_analysis.schemas import ScamAnalysisRequest, ScamAssessment
from ..services.ai_analysis.service import analyze_text

router = APIRouter(prefix="/api/v1", tags=["analysis"])

AI_MODEL_NAME = "openrouter"  # recorded in risk_assessments.engine_source context


@router.post("/analysis", response_model=ScamAssessment, status_code=201)
@limiter.limit("30/minute")
async def create_analysis(
    request: Request,
    payload: ScamAnalysisRequest,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
) -> ScamAssessment:
    """Analyze a suspicious message: AI/rules verdict + what led to it, saved to DB."""
    assessment = await analyze_text(payload.text)

    ai_used = assessment.source == "openrouter_ai_explanation"
    model_name = None
    if ai_used:
        config = OpenRouterConfig.from_env()
        model_name = f"openrouter/{config.model}"[:120]

    row = assessments_repo.create_assessment(
        db,
        user_id=user.user_id if user else None,
        input_content=payload.text,
        assessment=assessment,
        engine_source=AssessmentSource.HYBRID if ai_used else AssessmentSource.BASELINE_ENGINE,
        ai_model_name=model_name,
        ai_validated=True if ai_used else None,
    )
    db.commit()

    # assessment_id travels with the result so the report popup can link to it.
    return assessment.model_copy(update={"assessment_id": row.assessment_id})
