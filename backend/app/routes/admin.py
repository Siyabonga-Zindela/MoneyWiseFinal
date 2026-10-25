"""Admin endpoints for the System-Admin UI (admin-dashboard / admin-users).

The pages speak a small UI dialect (statuses new/reviewing/confirmed/dismissed,
org_type keys, 'invited' accounts). This router translates at the boundary so
the JS stays simple while the backend keeps its real model:
  - decisions become append-only scam_report_reviews rows (audit intact);
  - 'stakeholders' are real users with the STAKEHOLDER role + a profile row;
  - 'invited' means the account is ACTIVE but has not been handed over yet.

Auth: every endpoint requires a valid JWT with the ADMIN role (require_admin).
"""

import secrets
import string
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.deps import get_user_roles, require_admin
from ..core.security import hash_password
from ..db.session import get_db
from ..models.enums import AuditAction, ReportStatus, ReviewAction
from ..models.scam_report import ScamReport
from ..models.scam_report_review import ScamReportReview
from ..models.stakeholder import StakeholderProfile
from ..models.user import User, UserStatus
from ..repositories import audit as audit_repo
from ..repositories import reports as reports_repo
from ..repositories import stakeholders as stakeholder_repo
from ..repositories import tokens as tokens_repo
from ..repositories import users as users_repo
from ..schemas.review import ReviewCreate
from ..schemas.stakeholder import (
    AdminSummary,
    StakeholderCreate,
    StakeholderOut,
    StakeholderUpdate,
)
from ..services import report_service
from ..services.repeat_scam import repeat_counts_for_reports

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


def _generate_temp_password() -> str:
    """14-char password satisfying the register policy (upper + lower + digit)."""
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(14))
        if (
            any(c.isupper() for c in pw)
            and any(c.islower() for c in pw)
            and any(c.isdigit() for c in pw)
        ):
            return pw

# --- UI dialect mappings ------------------------------------------------------
REPORT_STATUS_TO_UI = {
    ReportStatus.SUBMITTED: "new",
    ReportStatus.UNDER_REVIEW: "reviewing",
    ReportStatus.REQUIRES_INVESTIGATION: "reviewing",
    ReportStatus.APPROVED: "confirmed",
    ReportStatus.REJECTED: "dismissed",
}
UI_TO_REVIEW_ACTION = {
    "confirmed": ReviewAction.APPROVED,
    "dismissed": ReviewAction.REJECTED,
}
RISK_TO_UI = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INCONCLUSIVE": "unsure"}
UI_STATUSES = ("new", "reviewing", "confirmed", "dismissed")


class AdminReportPatch(BaseModel):
    status: str = Field(description="new | reviewing | confirmed | dismissed")
    note: str | None = Field(default=None, max_length=4000)


class AdminReportForward(BaseModel):
    """Send a report to an external stakeholder inside MoneyWise."""

    stakeholder_user_id: int
    note: str | None = Field(default=None, max_length=2000)


def _ui_date(value: datetime | None) -> str:
    return value.date().isoformat() if value else ""


def _forward_maps(db: Session, report_ids: list[int]):
    """Forwards + acknowledgements for the given reports, keyed by report id."""
    sends = audit_repo.sends_for_reports(db, report_ids)
    acks = audit_repo.acks_for_reports(db, report_ids)
    # ack rows: entity_id = report_id, actor = stakeholder user id.
    ack_index = {}
    for ack in acks:
        key = (int(ack.details.get("report_id", 0) or 0) if ack.details else 0, ack.actor_user_id)
        if key[0] and key[1] and (key not in ack_index or ack.created_at > ack_index[key].created_at):
            ack_index[key] = ack

    forwards: dict[int, list[dict]] = {}
    for send in sends:
        details = send.details or {}
        report_id = int(details.get("report_id", 0) or 0)
        stakeholder_id = send.entity_id
        if not report_id or stakeholder_id is None:
            continue
        ack = ack_index.get((report_id, stakeholder_id))
        forwards.setdefault(report_id, []).append(
            {
                "stakeholder_id": stakeholder_id,
                "organisation": details.get("organisation", ""),
                "note": details.get("note") or "",
                "forwarded_by": details.get("forwarded_by", ""),
                "sent_at": send.created_at.isoformat() if send.created_at else None,
                "acknowledged": ack is not None,
                "acknowledged_at": ack.created_at.isoformat() if ack and ack.created_at else None,
            }
        )
    return forwards


def _report_to_ui(
    db: Session,
    r: ScamReport,
    repeat_count: int = 0,
    forwards: list[dict] | None = None,
) -> dict:
    """ScamReport -> the dict shape admin-dashboard.js renders."""
    latest_note = db.execute(
        select(ScamReportReview.notes)
        .where(ScamReportReview.report_id == r.report_id)
        .order_by(ScamReportReview.decided_at.desc(), ScamReportReview.review_id.desc())
        .limit(1)
    ).scalar_one_or_none()
    asked = float(r.amount_asked) if r.amount_asked is not None else 0
    promised = float(r.amount_promised) if r.amount_promised is not None else 0
    received = r.occurred_at or r.created_at
    return {
        "id": r.report_id,
        "phishing_type": r.phishing_type or "Other",
        "sender": r.reported_contact,
        "risk_level": RISK_TO_UI.get(r.risk_level.value if r.risk_level else "", "unsure"),
        "amount_asked": asked,
        "amount_promised": promised,
        "message": r.description,
        "date_received": _ui_date(received),
        "submitted_at": _ui_date(r.created_at),
        "status": REPORT_STATUS_TO_UI[r.status],
        "note": latest_note or "",
        # How many OTHER reports match this sender/provider (0 = first one).
        "repeat_count": repeat_count,
        # External handovers: [{stakeholder_id, organisation, note, sent_at,
        #   forwarded_by, acknowledged, acknowledged_at}]
        "forwarded_to": forwards or [],
        # Evidence files are never served by the API (identity-safety §8);
        # the panel hides the image block when this is empty.
        "screenshot_url": "",
    }


def _stakeholder_to_ui(user: User, profile: StakeholderProfile | None) -> dict:
    if user.status == UserStatus.SUSPENDED:
        status = "suspended"
    elif user.status == UserStatus.ACTIVE and profile is not None and profile.invite_pending:
        status = "invited"
    else:
        status = "active"
    return {
        "id": user.user_id,
        "name": user.full_name or "",
        "email": user.email,
        "organisation": profile.organisation if profile else "",
        "org_type": profile.org_type if profile else "other",
        "access": profile.access if profile else "view",
        "alerts": profile.alerts if profile else "none",
        "status": status,
        "last_active": _ui_date(profile.last_active_at) if profile and profile.last_active_at else "",
    }


def _stakeholder_user_or_404(db: Session, user_id: int) -> tuple[User, StakeholderProfile | None]:
    user = db.get(User, user_id)
    if user is None or user.status == UserStatus.DELETED:
        raise HTTPException(status_code=404, detail="Stakeholder not found")
    if "STAKEHOLDER" not in get_user_roles(db, user.user_id):
        raise HTTPException(status_code=404, detail="Stakeholder not found")
    return user, stakeholder_repo.profile_for_user(db, user_id)


# ---- reports -----------------------------------------------------------------


@router.get("/reports")
def admin_list_reports(
    status: str | None = Query(default=None, pattern="^(new|reviewing|confirmed|dismissed)$"),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> list[dict]:
    """All scam reports in the dashboard's dialect, newest submission first."""
    items, _total = reports_repo.list_all(db, limit=500, offset=0)
    repeat_counts = repeat_counts_for_reports(db, items)
    forwards = _forward_maps(db, [r.report_id for r in items])
    rows = [
        _report_to_ui(db, r, repeat_counts.get(r.report_id, 0), forwards.get(r.report_id))
        for r in items
    ]
    if status is not None:
        rows = [row for row in rows if row["status"] == status]
    rows.sort(key=lambda row: (row["submitted_at"], row["id"]), reverse=True)
    return rows


@router.patch("/reports/{report_id}")
def admin_patch_report(
    report_id: int,
    payload: AdminReportPatch,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict:
    """Dashboard 'Save changes': status + note.

    confirmed/dismissed become real decision rows (APPROVED/REJECTED);
    reviewing/new only move the workflow status. Finalised reports are 409.
    """
    if payload.status not in UI_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {', '.join(UI_STATUSES)}")

    report = reports_repo.get(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status in (ReportStatus.APPROVED, ReportStatus.REJECTED):
        raise HTTPException(
            status_code=409, detail="A final decision was already recorded for this report"
        )

    if payload.status in UI_TO_REVIEW_ACTION:
        _report, _review = report_service.review_report(
            db, admin, report_id,
            ReviewCreate(action=UI_TO_REVIEW_ACTION[payload.status], notes=payload.note),
        )
    else:
        target = ReportStatus.SUBMITTED if payload.status == "new" else ReportStatus.UNDER_REVIEW
        reports_repo.set_status(db, report, target)
        audit_repo.write(
            db,
            actor_user_id=admin.user_id,
            action=AuditAction.STATUS_CHANGE,
            entity_type="scam_report",
            entity_id=report.report_id,
            details={"status": payload.status, "note": payload.note or ""},
        )
        db.commit()
        db.refresh(report)

    repeat_counts = repeat_counts_for_reports(db, [report])
    forwards = _forward_maps(db, [report.report_id])
    return _report_to_ui(
        db,
        reports_repo.get(db, report_id),
        repeat_counts.get(report.report_id, 0),
        forwards.get(report.report_id),
    )


@router.post("/reports/{report_id}/forward")
def admin_forward_report(
    report_id: int,
    payload: AdminReportForward,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict:
    """Send a report to an external stakeholder inside MoneyWise.

    Built for impersonation reports: the admin picks the organisation being
    impersonated (the panel suggests stakeholders whose organisation name
    appears in the report) and the report appears in that partner's MoneyWise
    inbox. The handover is recorded once, in the append-only audit trail
    (entity_type=stakeholder_report_send) - no new tables, fully auditable.
    The report moves to REQUIRES_INVESTIGATION unless a final decision was
    already recorded.
    """
    report = reports_repo.get(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    user, profile = _stakeholder_user_or_404(db, payload.stakeholder_user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Stakeholder profile missing")

    status_changed = False
    if report.status not in (ReportStatus.APPROVED, ReportStatus.REJECTED):
        reports_repo.set_status(db, report, ReportStatus.REQUIRES_INVESTIGATION)
        status_changed = True

    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.STATUS_CHANGE if status_changed else AuditAction.UPDATE,
        entity_type="stakeholder_report_send",
        entity_id=user.user_id,
        details={
            "report_id": report.report_id,
            "report_title": report.title,
            "stakeholder_id": user.user_id,
            "organisation": profile.organisation,
            "stakeholder_email": user.email,
            "note": payload.note or "",
            "forwarded_by": admin.email,
        },
    )
    db.commit()
    db.refresh(report)

    repeat_counts = repeat_counts_for_reports(db, [report])
    forwards = _forward_maps(db, [report.report_id])
    return {
        "detail": f"Report sent to {profile.organisation} - it is now in their MoneyWise inbox.",
        "report": _report_to_ui(
            db,
            report,
            repeat_counts.get(report.report_id, 0),
            forwards.get(report.report_id),
        ),
    }


@router.get("/summary", response_model=AdminSummary)
def admin_summary(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> AdminSummary:
    """Counters for the admin-users page banner."""
    return AdminSummary(new_reports=stakeholder_repo.count_new_reports(db))


# ---- stakeholders ------------------------------------------------------------


@router.get("/stakeholders", response_model=list[StakeholderOut])
def admin_list_stakeholders(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> list[StakeholderOut]:
    ids = stakeholder_repo.stakeholder_user_ids(db)
    if not ids:
        return []
    profiles = stakeholder_repo.profiles_for_users(db, ids)
    users = db.execute(
        select(User).where(User.user_id.in_(ids)).order_by(User.user_id)
    ).scalars().all()
    return [StakeholderOut(**_stakeholder_to_ui(u, profiles.get(u.user_id))) for u in users]


@router.post("/stakeholders", response_model=StakeholderOut, status_code=201)
def admin_create_stakeholder(
    payload: StakeholderCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> StakeholderOut:
    """Create the account + profile and hand back a one-time temporary password.

    No mail provider is wired yet, so the admin passes the password to the
    partner over a secure channel; the account stays 'invited' until they
    first sign in.
    """
    existing = db.execute(
        select(User.user_id).where(User.email == payload.email)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="A stakeholder with this email already exists")

    temp_password = _generate_temp_password()
    user = users_repo.create_user(
        db,
        email=payload.email,
        password=temp_password,
        full_name=payload.name,
        roles=("STAKEHOLDER",),
    )
    profile = stakeholder_repo.create_profile(
        db,
        user.user_id,
        organisation=payload.organisation,
        org_type=payload.org_type,
        access=payload.access,
        alerts=payload.alerts,
    )
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.CREATE,
        entity_type="stakeholder",
        entity_id=user.user_id,
        details={"email": user.email, "organisation": profile.organisation},
    )
    db.commit()
    db.refresh(user)
    db.refresh(profile)
    out = _stakeholder_to_ui(user, profile)
    out["temporary_password"] = temp_password
    return StakeholderOut(**out)


@router.patch("/stakeholders/{user_id}", response_model=StakeholderOut)
def admin_update_stakeholder(
    user_id: int,
    payload: StakeholderUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> StakeholderOut:
    user, profile = _stakeholder_user_or_404(db, user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Stakeholder profile missing")

    if payload.name is not None:
        user.full_name = payload.name
    if payload.organisation is not None:
        profile.organisation = payload.organisation
    if payload.org_type is not None:
        profile.org_type = payload.org_type
    if payload.access is not None:
        profile.access = payload.access
    if payload.alerts is not None:
        profile.alerts = payload.alerts

    status_changed = False
    if payload.status is not None:
        if payload.status == "suspended":
            user.status = UserStatus.SUSPENDED
            status_changed = True
        elif payload.status == "active":
            user.status = UserStatus.ACTIVE
            profile.invite_pending = False
            status_changed = True
        elif payload.status == "invited":
            user.status = UserStatus.ACTIVE
            profile.invite_pending = True
            status_changed = True
        else:
            raise HTTPException(status_code=422, detail="status must be suspended, active or invited")

    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.STATUS_CHANGE if status_changed else AuditAction.UPDATE,
        entity_type="stakeholder",
        entity_id=user.user_id,
        details=payload.model_dump(exclude_none=True),
    )
    db.commit()
    db.refresh(user)
    db.refresh(profile)
    return StakeholderOut(**_stakeholder_to_ui(user, profile))


@router.delete("/stakeholders/{user_id}")
def admin_delete_stakeholder(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict:
    """Soft-delete: account can no longer sign in, history keeps its shape."""
    user, _profile = _stakeholder_user_or_404(db, user_id)
    user.status = UserStatus.DELETED
    stakeholder_repo.detach_role(db, user_id)
    tokens_repo.revoke_all_for_user(db, user_id)
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.DELETE,
        entity_type="stakeholder",
        entity_id=user.user_id,
        details={"email": user.email},
    )
    db.commit()
    return {"detail": "Stakeholder removed"}


@router.post("/stakeholders/{user_id}/resend", response_model=StakeholderOut)
def admin_resend_invitation(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> StakeholderOut:
    """Re-issue the invitation: a NEW temporary password is generated.

    With no mail provider wired, the new password is returned once for the
    admin to hand over securely (the old one is replaced, not recoverable).
    """
    user, profile = _stakeholder_user_or_404(db, user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Stakeholder profile missing")

    temp_password = _generate_temp_password()
    user.password_hash = hash_password(temp_password)
    user.status = UserStatus.ACTIVE
    profile.invite_pending = True
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.CONFIG_CHANGE,
        entity_type="stakeholder",
        entity_id=user.user_id,
        details={"action": "resend_invitation", "email": user.email},
    )
    db.commit()
    db.refresh(user)
    db.refresh(profile)
    out = _stakeholder_to_ui(user, profile)
    out["temporary_password"] = temp_password
    return StakeholderOut(**out)
