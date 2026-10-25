"""HTTP endpoints for text analysis.

The AI (OpenRouter, with the deterministic rule engine as the always-on
fallback) analyses the submitted text and returns the verdict plus WHAT LED
TO IT: the fired indicators (with the exact matched text), the explanation,
next steps and a 0-100 risk score. Every call is persisted to
risk_assessments + assessment_evidence so reports can reference it and the
explainability trail survives (§6).
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import OperationalError
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
from ..services.repeat_scam import signal_for

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
    """Analyze a suspicious message: AI/rules verdict + what led to it, saved to DB.

    When the optional `sender` field is supplied, the report history is
    checked first: a sender/provider that was reported before escalates the
    deterministic verdict to a repetitive-scam HIGH (real counts from
    scam_reports, never invented), and the AI explanation mentions it.
    """
    try:
        repeat = signal_for(db, contact=payload.sender, text=payload.text)
    except OperationalError:
        # History lookup needs the DB; if it is unreachable we still run the
        # check itself (the save below will surface the proper 503 guidance).
        repeat = None
    assessment = await analyze_text(payload.text, repeat=repeat)

    ai_used = assessment.source == "openrouter_ai_explanation"
    model_name = None
    if ai_used:
        config = OpenRouterConfig.from_env()
        model_name = f"openrouter/{config.model}"[:120]

    try:
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
    except OperationalError as exc:
        # The verdict was computed, but persisting it failed - in practice this
        # means the configured database is unreachable, which would otherwise
        # surface as a bare 500 with no clue for the operator. Give DIFFERENT
        # guidance per failure mode: a TCP "timeout expired" usually means the
        # local network is blocking port 5432 (VPN / campus WiFi / antivirus),
        # NOT a bad .env - sending the user to edit a correct .env wastes time.
        reason = str(exc).splitlines()[0][:200]
        low = str(exc).lower()
        if "timeout expired" in low or "timed out" in low:
            guidance = (
                "Your .env is probably fine - the connection to Neon on port 5432 "
                "TIMED OUT, so something on this machine or network is blocking it "
                "(VPN, campus/office WiFi, antivirus firewall, or a momentary drop). "
                "First try: python doctor.py again; if it still times out, test with "
                "PowerShell: Test-NetConnection ep-small-hill-b42y905s-pooler.c-6."
                "us-east-2.aws.neon.tech -Port 5432 - or switch to a phone hotspot."
            )
        else:
            guidance = (
                "Fix your backend/.env DATABASE_URL (Neon, with ?sslmode=require), "
                "then run: python doctor.py."
            )
        raise HTTPException(
            status_code=503,
            detail=(
                "The check ran, but saving the result failed because the database "
                "is unreachable. " + guidance + " Server said: " + reason
            ),
        ) from exc

    # assessment_id travels with the result so the report popup can link to it.
    return assessment.model_copy(update={"assessment_id": row.assessment_id})
