"""Scam report endpoints - users file and track their own; admins see and moderate all.

POST /api/v1/reports accepts BOTH:
  - application/json    (original API shape OR the popup's field names)
  - multipart/form-data (the popup form, including the optional screenshot)

Screenshots: PNG/JPG only, max 5 MB, stored under backend/uploads/reports/;
the stored relative path is returned as screenshot_path. Raw files are never
served by the API (identity-safety, §8) - that is a separate concern.
"""

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile
from sqlalchemy.orm import Session

from ..core.deps import client_ip, get_current_user, get_user_roles, require_admin
from ..core.security import hash_ip
from ..db.session import get_db
from ..models.enums import ReportStatus
from ..models.scam_report import ScamReport
from ..models.user import User
from ..repositories import reports as reports_repo
from ..repositories import reviews as reviews_repo
from ..schemas.common import Page
from ..schemas.report import ReportCreate, ReportOut, VisibilityUpdate
from ..schemas.review import ReviewOut
from ..services import report_service

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

UPLOAD_DIR = Path(__file__).resolve().parents[2] / "uploads" / "reports"
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
ALLOWED_SCREENSHOT_TYPES = {"image/png": ".png", "image/jpeg": ".jpg"}

FORM_TEXT_FIELDS = (
    "title", "description", "channel", "reported_url", "reported_contact",
    "phishing_type", "message", "risk_level", "sender", "assessment_id",
)
FORM_AMOUNT_FIELDS = ("amount_asked", "amount_promised")
FORM_DATE_FIELDS = ("date_received",)


def _store_screenshot(upload: UploadFile) -> str:
    """Validate + persist the popup screenshot. Returns the stored relative path."""
    if upload.content_type not in ALLOWED_SCREENSHOT_TYPES:
        raise HTTPException(
            status_code=415, detail="Screenshot must be a PNG or JPG image"
        )
    data = upload.file.read(MAX_SCREENSHOT_BYTES + 1)
    if len(data) > MAX_SCREENSHOT_BYTES:
        raise HTTPException(status_code=413, detail="Screenshot must be 5 MB or smaller")
    if not data:
        raise HTTPException(status_code=400, detail="Screenshot file is empty")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    suffix = ALLOWED_SCREENSHOT_TYPES[upload.content_type]
    filename = f"{uuid.uuid4().hex}{suffix}"
    (UPLOAD_DIR / filename).write_bytes(data)
    return f"uploads/reports/{filename}"


def _payload_from_form(form) -> ReportCreate:
    """Build ReportCreate from the popup's multipart form fields."""
    data: dict = {}
    for field in FORM_TEXT_FIELDS:
        value = form.get(field)
        if value not in (None, ""):
            data[field] = value
    for field in FORM_AMOUNT_FIELDS:
        value = form.get(field)
        if value not in (None, ""):
            data[field] = value
    for field in FORM_DATE_FIELDS:
        value = form.get(field)
        if value not in (None, ""):
            data[field] = value

    # File inputs submit "screenshot"; ignore empty placeholder values.
    try:
        return ReportCreate(**data)
    except Exception as exc:  # surface pydantic errors as a clean 422
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("", response_model=ReportOut, status_code=201)
async def create_report(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ScamReport:
    """File a new scam report (JSON or the popup's multipart form with screenshot).

    Duplicate content is LINKED, never merged (§8). If the popup sent the
    assessment_id from /analysis, the report is linked to that AI verdict.
    """
    content_type = request.headers.get("content-type", "")
    screenshot_path: str | None = None

    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        payload = _payload_from_form(form)
        upload = form.get("screenshot")
        if upload is not None and getattr(upload, "filename", None):
            screenshot_path = _store_screenshot(upload)
    else:
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON body") from exc
        try:
            payload = ReportCreate(**body)
        except Exception as exc:  # surface pydantic errors as a clean 422
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return report_service.create_report(
        db, user, payload,
        ip_hash_value=hash_ip(client_ip(request)),
        screenshot_path=screenshot_path,
    )


@router.get("", response_model=Page[ReportOut])
def list_reports(
    scope: str = Query(default="mine", pattern="^(mine|all)$"),
    status: ReportStatus | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """scope=mine (default) lists my reports; scope=all is admin-only."""
    if scope == "all":
        if "ADMIN" not in get_user_roles(db, user.user_id):
            raise HTTPException(status_code=403, detail="Administrator privileges required")
        items, total = reports_repo.list_all(db, status=status, limit=limit, offset=offset)
    else:
        items, total = reports_repo.list_for_user(
            db, user.user_id, limit=limit, offset=offset
        )
    return Page(items=items, total=total, limit=limit, offset=offset)


def _report_or_denied(db: Session, report_id: int, user: User) -> ScamReport:
    report = reports_repo.get(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    is_admin = "ADMIN" in get_user_roles(db, user.user_id)
    if report.reporter_id != user.user_id and not is_admin:
        raise HTTPException(status_code=403, detail="You can only access your own reports")
    return report


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ScamReport:
    return _report_or_denied(db, report_id, user)


@router.get("/{report_id}/reviews", response_model=list[ReviewOut])
def report_reviews(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Decision trail for a report (owner or admin)."""
    report = _report_or_denied(db, report_id, user)
    return reviews_repo.list_for_report(db, report.report_id)


@router.patch("/{report_id}/visibility", response_model=ReportOut)
def set_visibility(
    report_id: int,
    payload: VisibilityUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> ScamReport:
    """Admin-only: publish/unpublish a report (identity-safe, off by default)."""
    report = reports_repo.get(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_service.set_visibility(
        db, admin, report, payload, ip_hash_value=hash_ip(client_ip(request))
    )
