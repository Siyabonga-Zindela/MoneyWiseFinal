"""FastAPI application entry point - all routers are wired here.

The user's backend half owns this file (team boundary contract). The partner's
/api/v1/analysis router stays mounted unchanged so their AI work keeps working.
"""

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.orm import Session

from .core.config import settings
from .core.rate_limit import limiter
from .db.session import get_db
from .routes.analysis import router as analysis_router
from .routes.audit import router as audit_router
from .routes.auth import router as auth_router
from .routes.education import router as education_router
from .routes.privacy import router as privacy_router
from .routes.reports import router as reports_router
from .routes.reviews import router as reviews_router

app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description=(
        "AI-powered scam & investment protection - "
        "auth, scam reports, admin reviews, education centre, POPIA privacy, audit trail."
    ),
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in (
    analysis_router,
    auth_router,
    reports_router,
    reviews_router,
    education_router,
    privacy_router,
    audit_router,
):
    app.include_router(router)


@app.get("/health", tags=["health"])
def health(db: Session = Depends(get_db)):
    """Liveness + database connectivity probe."""
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(
            status_code=503, content={"status": "degraded", "database": "unavailable"}
        )
    return {
        "status": "ok",
        "database": "ok",
        "environment": settings.environment,
    }
