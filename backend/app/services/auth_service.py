"""Authentication business logic: register, login (+lockout), refresh rotation, logout."""

import jwt as pyjwt
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.deps import get_user_roles
from ..core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from ..models.enums import AuditAction, UserStatus
from ..models.user import User
from ..repositories import audit as audit_repo
from ..repositories import login_attempts as attempts_repo
from ..repositories import tokens as tokens_repo
from ..repositories import users as users_repo
from ..schemas.auth import LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest, TokenResponse, UserOut


def _token_response(db: Session, user: User, *, refresh_token: str, expires_at: datetime) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(user.user_id, get_user_roles(db, user.user_id)),
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserOut(
            user_id=user.user_id,
            email=user.email,
            full_name=user.full_name,
            phone=user.phone,
            status=user.status.value,
            roles=get_user_roles(db, user.user_id),
            created_at=user.created_at,
        ),
    )


def _issue_session(db: Session, user: User, *, ip_hash_value: str | None, user_agent: str | None) -> TokenResponse:
    refresh_token, _jti, expires_at = create_refresh_token(user.user_id)
    tokens_repo.store(
        db,
        user.user_id,
        refresh_token,
        expires_at,
        user_agent=user_agent,
        ip_hash=ip_hash_value,
    )
    response = _token_response(db, user, refresh_token=refresh_token, expires_at=expires_at)
    db.commit()
    return response


def register(
    db: Session,
    payload: RegisterRequest,
    *,
    ip_hash_value: str | None = None,
    user_agent: str | None = None,
) -> TokenResponse:
    if users_repo.get_by_email(db, payload.email) is not None:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = users_repo.create_user(
        db,
        payload.email,
        payload.password,
        full_name=payload.full_name,
        phone=payload.phone,
    )
    audit_repo.write(
        db,
        actor_user_id=user.user_id,
        action=AuditAction.CREATE,
        entity_type="user",
        entity_id=user.user_id,
        details={"email": user.email, "via": "register"},
    )
    return _issue_session(db, user, ip_hash_value=ip_hash_value, user_agent=user_agent)


def login(
    db: Session,
    payload: LoginRequest,
    *,
    ip_hash_value: str | None = None,
    user_agent: str | None = None,
) -> TokenResponse:
    email = payload.email
    user = users_repo.get_by_email(db, email)
    now = datetime.now(timezone.utc)

    if user is None:
        attempts_repo.record(
            db, email, success=False, ip_hash=ip_hash_value, failure_reason="UNKNOWN_EMAIL"
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.status is not UserStatus.ACTIVE:
        attempts_repo.record(
            db, email, success=False, user_id=user.user_id,
            ip_hash=ip_hash_value, failure_reason="ACCOUNT_INACTIVE",
        )
        audit_repo.write(
            db, actor_user_id=user.user_id, action=AuditAction.LOGIN_FAILED,
            entity_type="user", entity_id=user.user_id,
            details={"reason": "ACCOUNT_INACTIVE"}, ip_hash=ip_hash_value,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Account is not active")

    if user.locked_until is not None and user.locked_until > now:
        attempts_repo.record(
            db, email, success=False, user_id=user.user_id,
            ip_hash=ip_hash_value, failure_reason="ACCOUNT_LOCKED",
        )
        db.commit()
        raise HTTPException(status_code=423, detail="Account temporarily locked - try again later")

    if not verify_password(payload.password, user.password_hash):
        failures = attempts_repo.count_recent_failures(
            db, email, settings.failed_login_window_minutes
        )
        will_lock = failures + 1 >= settings.failed_login_max_attempts
        if will_lock:
            users_repo.lock_account(db, user, settings.account_lock_minutes)
        attempts_repo.record(
            db, email, success=False, user_id=user.user_id, ip_hash=ip_hash_value,
            failure_reason="INVALID_PASSWORD_LOCKED" if will_lock else "INVALID_PASSWORD",
        )
        audit_repo.write(
            db, actor_user_id=user.user_id, action=AuditAction.LOGIN_FAILED,
            entity_type="user", entity_id=user.user_id,
            details={"attempt": failures + 1, "locked": will_lock}, ip_hash=ip_hash_value,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # --- success -------------------------------------------------------------
    users_repo.clear_lock(db, user)
    users_repo.set_last_login(db, user)
    attempts_repo.record(db, email, success=True, user_id=user.user_id, ip_hash=ip_hash_value)
    audit_repo.write(
        db, actor_user_id=user.user_id, action=AuditAction.LOGIN,
        entity_type="user", entity_id=user.user_id, ip_hash=ip_hash_value,
    )
    return _issue_session(db, user, ip_hash_value=ip_hash_value, user_agent=user_agent)


def refresh(db: Session, payload: RefreshRequest) -> TokenResponse:
    try:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    row = tokens_repo.get_active_by_hash(db, payload.refresh_token)
    if row is None or row.user_id != int(claims["sub"]):
        # Unknown, revoked (reuse after rotation!) or expired token.
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid")

    user = users_repo.get(db, row.user_id)
    if user is None or user.status is not UserStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid")

    # Rotation: the presented refresh token dies, a brand-new pair is issued.
    tokens_repo.revoke(db, row)
    return _issue_session(db, user, ip_hash_value=None, user_agent=None)


def logout(
    db: Session,
    user: User,
    payload: LogoutRequest,
    *,
    ip_hash_value: str | None = None,
) -> None:
    if payload.refresh_token:
        row = tokens_repo.get_active_by_hash(db, payload.refresh_token)
        if row is not None and row.user_id == user.user_id:
            tokens_repo.revoke(db, row)
    else:
        tokens_repo.revoke_all_for_user(db, user.user_id)
    audit_repo.write(
        db, actor_user_id=user.user_id, action=AuditAction.LOGOUT,
        entity_type="user", entity_id=user.user_id, ip_hash=ip_hash_value,
    )
    db.commit()
