"""FastAPI application entry point - all routers are wired here.

The user's backend half owns this file (team boundary contract). The partner's
/api/v1/analysis router stays mounted unchanged so their AI work keeps working.

The frontend is served from this same origin (mounted LAST so /api/v1/* keeps
priority): opening http://127.0.0.1:8000/ serves frontend/index.html directly,
so the pages and the API share one origin - no CORS surprises, no drift.

Security middleware (added before the routes are mounted):
- SecurityHeaders: CSP, nosniff, frame denial, referrer policy on every
  response (HSTS only in production, where TLS terminates in front of us).
- BodySizeLimit: rejects requests whose declared Content-Length exceeds
  settings.max_body_mb (413) so oversized uploads never reach the handlers.
"""

from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from .core.config import settings
from .core.rate_limit import limiter
from .db.session import get_db
from .routes.admin import router as admin_router
from .routes.analysis import router as analysis_router
from .routes.audit import router as audit_router
from .routes.auth import router as auth_router
from .routes.education import router as education_router
from .routes.privacy import router as privacy_router
from .routes.reports import router as reports_router
from .routes.reviews import router as reviews_router
from .routes.stakeholder import router as stakeholder_router

app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description=(
        "AI-powered scam & investment protection - "
        "auth, scam reports, admin reviews, education centre, POPIA privacy, audit trail."
    ),
)


# --- startup database self-check -------------------------------------------------
# The engine is lazy: a wrong DATABASE_URL only explodes mid-request as a raw
# 500. This probe surfaces the real problem at boot, where it is obvious.

def _masked_db_url() -> str:
    try:
        from sqlalchemy.engine import make_url

        url = make_url(settings.database_url)
        return f"{url.drivername}://{url.username}:***@{url.host}:{url.port}/{url.database}"
    except Exception:  # noqa: BLE001 - masking must never crash startup
        return "(unparseable URL)"


@app.on_event("startup")
def startup_database_check() -> None:
    from .db.session import engine

    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception as exc:  # noqa: BLE001 - any failure must not block startup
        short = str(exc).splitlines()[0][:160]
        print("", flush=True)
        print("=" * 68, flush=True)
        print("WARNING: DATABASE UNREACHABLE", flush=True)
        print(f"  Trying : {_masked_db_url()}", flush=True)
        print(f"  Error  : {short}", flush=True)
        print("  Effect : pages load, but login / check / report will return 500.", flush=True)
        print("  Fix    : put your Neon connection string in backend/.env as", flush=True)
        print("             DATABASE_URL=postgresql://USER:PASSWORD@HOST/neondb?sslmode=require", flush=True)
        print("           then run:  python doctor.py   (in the backend folder)", flush=True)
        print("=" * 68, flush=True)
        print("", flush=True)
        return
    print(f"Database connection OK ({_masked_db_url()})", flush=True)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# --- security headers ---------------------------------------------------------

# style-src keeps 'unsafe-inline' because report-popup.js injects its own
# <style> element and the login page carries two tiny style="" attributes.
# script-src stays strict: every script is a same-origin file, so a single
# XSS injection cannot also smuggle inline script.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if settings.environment == "production":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests that declare a Content-Length above the cap.

    The screenshot upload path re-validates the actual bytes (5 MB), so this
    is a coarse guard against trivially oversized requests, not the only one.
    Chunked bodies (no Content-Length) are capped by the per-endpoint schema
    limits (analysis text <= 5000 chars, screenshot read <= 5 MB + 1 byte).
    """

    MAX_BYTES = settings.max_body_mb * 1024 * 1024

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > self.MAX_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )
        return await call_next(request)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodySizeLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

for router in (
    analysis_router,
    auth_router,
    reports_router,
    reviews_router,
    education_router,
    privacy_router,
    audit_router,
    admin_router,
    stakeholder_router,
):
    app.include_router(router)


@app.get("/health", tags=["health"])
def health(db: Session = Depends(get_db)):
    """Liveness + database connectivity probe.

    Deliberately reports nothing else: no environment name, no versions,
    no configuration detail (§4 - no internal details exposed).
    """
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(
            status_code=503, content={"status": "degraded", "database": "unavailable"}
        )
    return {"status": "ok", "database": "ok"}


# --- combined frontend + backend serving -------------------------------------
# Mounted LAST so /api/v1/* and /health always win. With this, `uvicorn
# app.main:app` serves the whole product from one origin and the frontend's
# same-origin API calls need no configuration at all.
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
