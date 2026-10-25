"""Auth endpoints: register, login, refresh, logout, me."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.deps import client_ip, get_current_user, get_user_roles
from ..core.rate_limit import limiter
from ..core.security import hash_ip
from ..db.session import get_db
from ..models.user import User
from ..schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
)
from ..schemas.common import MessageResponse
from ..services import auth_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=201)
@limiter.limit(settings.rate_limit_auth)
def register(
    request: Request,
    payload: RegisterRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Create an account (USER role assigned) and return the first token pair."""
    return auth_service.register(
        db,
        payload,
        ip_hash_value=hash_ip(client_ip(request)),
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.rate_limit_auth)
def login(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Password login with lockout after repeated failures (login_attempts backed)."""
    return auth_service.login(
        db,
        payload,
        ip_hash_value=hash_ip(client_ip(request)),
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    payload: RefreshRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Rotate the refresh token: the presented one dies, a fresh pair is issued."""
    return auth_service.refresh(db, payload)


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    payload: LogoutRequest | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MessageResponse:
    """Revoke the given refresh token, or ALL my sessions when no token is sent."""
    auth_service.logout(
        db,
        user,
        payload or LogoutRequest(),
        ip_hash_value=hash_ip(client_ip(request)),
    )
    return MessageResponse(detail="Logged out")


@router.get("/me", response_model=UserOut)
def me(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> UserOut:
    """POPIA data access right: the account holder can read their own profile."""
    return UserOut(
        user_id=user.user_id,
        email=user.email,
        full_name=user.full_name,
        phone=user.phone,
        status=user.status.value,
        roles=get_user_roles(db, user.user_id),
        created_at=user.created_at,
    )
