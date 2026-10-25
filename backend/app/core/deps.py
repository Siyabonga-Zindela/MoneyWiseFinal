"""Shared FastAPI dependencies: DB session is in app.db.session; user + admin here."""

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.session import get_db
from ..models.role import Role
from ..models.user import User, UserStatus
from ..models.user_role import UserRole
from .security import decode_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_user_roles(db: Session, user_id: int) -> list[str]:
    stmt = (
        select(Role.role_name)
        .join(UserRole, UserRole.role_id == Role.role_id)
        .where(UserRole.user_id == user_id)
    )
    return list(db.scalars(stmt).all())


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the Bearer access token to an ACTIVE user, else 401/403."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    if user.status is not UserStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Account is not active")
    return user


def require_admin(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Partner-facing contract: gate any admin-only endpoint with this dependency."""
    if "ADMIN" not in get_user_roles(db, user.user_id):
        raise HTTPException(status_code=403, detail="Administrator privileges required")
    return user


def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User | None:
    """Resolve the Bearer token when one is supplied, else None.

    Used by open endpoints (e.g. /analysis) that personalise history for
    logged-in users but also serve anonymous visitors. A supplied-but-invalid
    token still 401s so broken clients are not silently ignored.
    """
    if credentials is None or not credentials.credentials:
        return None
    return get_current_user(credentials=credentials, db=db)


def client_ip(request: Request) -> str:
    """Best-effort client IP (respects x-forwarded-for from reverse proxies)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
