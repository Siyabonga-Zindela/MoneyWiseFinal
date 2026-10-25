"""Repository: stakeholder profiles + offers + STAKEHOLDER role helpers."""

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..models.role import Role
from ..models.stakeholder import StakeholderOffer, StakeholderProfile
from ..models.user import User, UserStatus
from ..models.user_role import UserRole


def stakeholder_role_id(db: Session) -> int | None:
    return db.execute(
        select(Role.role_id).where(Role.role_name == "STAKEHOLDER")
    ).scalar()


def stakeholder_user_ids(db: Session) -> list[int]:
    """IDs of every non-deleted user carrying the STAKEHOLDER role."""
    role_id = stakeholder_role_id(db)
    if role_id is None:
        return []
    rows = db.execute(
        select(UserRole.user_id)
        .join(User, User.user_id == UserRole.user_id)
        .where(UserRole.role_id == role_id, User.status != UserStatus.DELETED)
    ).scalars().all()
    return list(rows)


def profiles_for_users(db: Session, user_ids: list[int]) -> dict[int, StakeholderProfile]:
    if not user_ids:
        return {}
    rows = db.execute(
        select(StakeholderProfile).where(StakeholderProfile.user_id.in_(user_ids))
    ).scalars().all()
    return {p.user_id: p for p in rows}


def profile_for_user(db: Session, user_id: int) -> StakeholderProfile | None:
    return db.execute(
        select(StakeholderProfile).where(StakeholderProfile.user_id == user_id)
    ).scalar_one_or_none()


def create_profile(
    db: Session,
    user_id: int,
    *,
    organisation: str,
    org_type: str,
    access: str,
    alerts: str,
    invite_pending: bool = True,
) -> StakeholderProfile:
    profile = StakeholderProfile(
        user_id=user_id,
        organisation=organisation,
        org_type=org_type,
        access=access,
        alerts=alerts,
        invite_pending=invite_pending,
    )
    db.add(profile)
    db.flush()
    return profile


def attach_role(db: Session, user_id: int) -> None:
    role_id = stakeholder_role_id(db)
    if role_id is None:
        raise ValueError("role not seeded in roles table: STAKEHOLDER")
    exists = db.execute(
        select(UserRole.role_id).where(
            UserRole.user_id == user_id, UserRole.role_id == role_id
        )
    ).scalar_one_or_none()
    if exists is None:
        db.add(UserRole(user_id=user_id, role_id=role_id))
        db.flush()


def detach_role(db: Session, user_id: int) -> None:
    role_id = stakeholder_role_id(db)
    if role_id is not None:
        db.execute(
            delete(UserRole).where(
                UserRole.user_id == user_id, UserRole.role_id == role_id
            )
        )


def touch_last_active(db: Session, user_id: int) -> None:
    profile = profile_for_user(db, user_id)
    if profile is not None:
        profile.last_active_at = func.now()
        db.flush()


# ---- offers -----------------------------------------------------------------


def offers_for_user(db: Session, user_id: int) -> list[StakeholderOffer]:
    return list(
        db.execute(
            select(StakeholderOffer)
            .where(StakeholderOffer.user_id == user_id)
            .order_by(StakeholderOffer.updated_at.desc(), StakeholderOffer.offer_id.desc())
        ).scalars().all()
    )


def offer_get(db: Session, offer_id: int) -> StakeholderOffer | None:
    return db.execute(
        select(StakeholderOffer).where(StakeholderOffer.offer_id == offer_id)
    ).scalar_one_or_none()


def count_new_reports(db: Session) -> int:
    from ..models.enums import ReportStatus
    from ..models.scam_report import ScamReport

    return int(
        db.execute(
            select(func.count())
            .select_from(ScamReport)
            .where(ScamReport.status == ReportStatus.SUBMITTED)
        ).scalar_one()
    )
