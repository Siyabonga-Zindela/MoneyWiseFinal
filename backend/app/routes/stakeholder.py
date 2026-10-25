"""External-stakeholder endpoints: the partner's investment offers + the
report inbox the admin forwards impersonation reports into.

externalStakeholder.js lists and updates offers and shows reports shared with
the organisation; column names mirror its form fields exactly. Auth: a JWT
with the STAKEHOLDER role (admins may also manage offers so support is
possible). Listing an offer touches last_active_at so the admin-users screen
shows real 'Last active' data.

Report forwarding lives in the append-only audit trail (entity_type
stakeholder_report_send / stakeholder_report_ack) - no new tables, and every
handover stays auditable.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..core.deps import get_current_user, get_user_roles
from ..db.session import get_db
from ..models.enums import AuditAction, ReportStatus, RiskCategoryDB
from ..models.stakeholder import StakeholderOffer
from ..models.user import User
from ..repositories import audit as audit_repo
from ..repositories import stakeholders as stakeholder_repo
from ..schemas.stakeholder import OfferCreate, OfferOut, OfferUpdate

router = APIRouter(prefix="/api/v1/stakeholder", tags=["stakeholder"])


def require_stakeholder(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> User:
    roles = get_user_roles(db, user.user_id)
    if "STAKEHOLDER" not in roles and "ADMIN" not in roles:
        raise HTTPException(status_code=403, detail="Stakeholder privileges required")
    return user


def _own_offer_or_denied(db: Session, offer_id: int, user: User) -> StakeholderOffer:
    offer = stakeholder_repo.offer_get(db, offer_id)
    if offer is None:
        raise HTTPException(status_code=404, detail="Offer not found")
    is_admin = "ADMIN" in get_user_roles(db, user.user_id)
    if offer.user_id != user.user_id and not is_admin:
        raise HTTPException(status_code=403, detail="You can only manage your own offers")
    return offer


@router.get("/offers", response_model=list[OfferOut])
def my_offers(
    db: Session = Depends(get_db),
    user: User = Depends(require_stakeholder),
) -> list[StakeholderOffer]:
    stakeholder_repo.touch_last_active(db, user.user_id)
    db.commit()
    return stakeholder_repo.offers_for_user(db, user.user_id)


@router.post("/offers", response_model=OfferOut, status_code=201)
def create_offer(
    payload: OfferCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_stakeholder),
) -> StakeholderOffer:
    offer = StakeholderOffer(
        user_id=user.user_id,
        product_name=payload.product_name,
        product_category=payload.product_category,
        description=payload.description,
        currency="ZAR",
        min_investment=payload.min_investment,
        max_investment=payload.max_investment,
        fees_summary=payload.fees_summary,
        indicative_return_range=payload.indicative_return_range,
        access_condition=payload.access_condition,
        material_risk=payload.material_risk,
        suitable_timeframe=payload.suitable_timeframe,
        url=payload.url,
    )
    db.add(offer)
    audit_repo.write(
        db,
        actor_user_id=user.user_id,
        action=AuditAction.CREATE,
        entity_type="stakeholder_offer",
        entity_id=offer.offer_id,
        details={"product_name": offer.product_name},
    )
    db.commit()
    db.refresh(offer)
    return offer


@router.patch("/offers/{offer_id}", response_model=OfferOut)
def update_offer(
    offer_id: int,
    payload: OfferUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_stakeholder),
) -> StakeholderOffer:
    """Only the three post-publication-editable columns may change."""
    offer = _own_offer_or_denied(db, offer_id, user)

    new_min = payload.min_investment if payload.min_investment is not None else offer.min_investment
    new_max = payload.max_investment if payload.max_investment is not None else offer.max_investment
    if new_max < new_min:
        raise HTTPException(status_code=422, detail="max_investment must be at least min_investment")

    if payload.min_investment is not None:
        offer.min_investment = payload.min_investment
    if payload.max_investment is not None:
        offer.max_investment = payload.max_investment
    if payload.indicative_return_range is not None:
        offer.indicative_return_range = payload.indicative_return_range

    audit_repo.write(
        db,
        actor_user_id=user.user_id,
        action=AuditAction.UPDATE,
        entity_type="stakeholder_offer",
        entity_id=offer.offer_id,
        details=payload.model_dump(exclude_none=True, mode="json"),
    )
    db.commit()
    db.refresh(offer)
    return offer


@router.delete("/offers/{offer_id}")
def delete_offer(
    offer_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_stakeholder),
) -> dict:
    offer = _own_offer_or_denied(db, offer_id, user)
    db.delete(offer)
    audit_repo.write(
        db,
        actor_user_id=user.user_id,
        action=AuditAction.DELETE,
        entity_type="stakeholder_offer",
        entity_id=offer_id,
        details={"product_name": offer.product_name},
    )
    db.commit()
    return {"detail": "Offer removed"}


# ---- report inbox ------------------------------------------------------------
# Reports an admin forwarded to THIS stakeholder (e.g. a bank being
# impersonated). Identity-safe: the reporter is never exposed - the partner
# only sees the report content and the admin's note.

RISK_TO_UI = {r.value: r.value.lower() for r in RiskCategoryDB}


def _my_send_rows(db: Session, user: User) -> list:
    return audit_repo.sends_for_stakeholder(db, user.user_id)


def _inbox_item(db: Session, send, acks_by_report: dict[int, datetime]) -> dict | None:
    """One forwarded report as the partner sees it (None if report is gone)."""
    details = send.details or {}
    try:
        report_id = int(details.get("report_id", 0) or 0)
    except (TypeError, ValueError):
        return None
    from ..models.scam_report import ScamReport

    report = db.get(ScamReport, report_id)
    if report is None:
        return None
    received = report.occurred_at or report.created_at
    return {
        "report_id": report.report_id,
        "title": report.title,
        "phishing_type": report.phishing_type or "Other",
        "channel": report.channel.value,
        "message": report.description,
        # The SCAMMER's contact - the partner needs it to act; the reporter
        # stays anonymous (identity-safety §8).
        "sender": report.reported_contact,
        "risk_level": RISK_TO_UI.get(report.risk_level.value if report.risk_level else "", "unsure"),
        "status": report.status.value,
        "amount_asked": float(report.amount_asked) if report.amount_asked is not None else None,
        "amount_promised": float(report.amount_promised) if report.amount_promised is not None else None,
        "date_received": received.date().isoformat() if received else None,
        "sent_at": send.created_at.isoformat() if send.created_at else None,
        "note": details.get("note") or "",
        "forwarded_by": details.get("forwarded_by") or "",
        "organisation": details.get("organisation") or "",
        "acknowledged": report.report_id in acks_by_report,
        "acknowledged_at": (
            acks_by_report[report.report_id].isoformat()
            if report.report_id in acks_by_report
            else None
        ),
    }


@router.get("/reports")
def my_shared_reports(
    db: Session = Depends(get_db),
    user: User = Depends(require_stakeholder),
) -> list[dict]:
    """Reports the admin has sent to this stakeholder, newest handover first."""
    stakeholder_repo.touch_last_active(db, user.user_id)
    sends = _my_send_rows(db, user)
    if not sends:
        db.commit()
        return []

    acks_by_report: dict[int, datetime] = {}
    send_report_ids: list[int] = []
    for send in sends:
        details = send.details or {}
        try:
            rid = int(details.get("report_id", 0) or 0)
        except (TypeError, ValueError):
            continue
        if rid:
            send_report_ids.append(rid)
    for ack in audit_repo.acks_for_reports(db, send_report_ids):
        if ack.actor_user_id != user.user_id:
            continue
        try:
            rid = int(ack.details.get("report_id", 0) or 0) if ack.details else 0
        except (TypeError, ValueError):
            continue
        if rid and (rid not in acks_by_report or (ack.created_at and ack.created_at > acks_by_report[rid])):
            acks_by_report[rid] = ack.created_at

    items = []
    seen: set[int] = set()
    for send in reversed(sends):  # newest handover first
        item = _inbox_item(db, send, acks_by_report)
        if item is None or item["report_id"] in seen:
            continue
        seen.add(item["report_id"])
        items.append(item)
    db.commit()
    return items


@router.post("/reports/{report_id}/acknowledge")
def acknowledge_shared_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_stakeholder),
) -> dict:
    """Confirm receipt: the admin dashboard then shows the report as seen."""
    sent_to_me = any(
        (send.details or {}).get("report_id") in (report_id, str(report_id))
        for send in _my_send_rows(db, user)
    )
    if not sent_to_me:
        raise HTTPException(status_code=404, detail="No report was sent to you with this id")

    from ..models.scam_report import ScamReport

    report = db.get(ScamReport, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    profile = stakeholder_repo.profile_for_user(db, user.user_id)
    audit_repo.write(
        db,
        actor_user_id=user.user_id,
        action=AuditAction.STATUS_CHANGE,
        entity_type=audit_repo.ACK_ENTITY,
        entity_id=report.report_id,
        details={
            "report_id": report.report_id,
            "stakeholder_id": user.user_id,
            "organisation": profile.organisation if profile else "",
        },
    )
    db.commit()
    return {
        "detail": "Marked as received - the MoneyWise team can see the confirmation.",
        "report_id": report.report_id,
        "acknowledged_at": datetime.now(timezone.utc).isoformat(),
    }
