"""User + role data access."""

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.security import hash_password
from ..models.role import Role
from ..models.user import User, UserStatus
from ..models.user_role import UserRole


def get(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def get_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def create_user(
    db: Session,
    email: str,
    password: str,
    full_name: str | None = None,
    phone: str | None = None,
    roles: tuple[str, ...] = ("USER",),
) -> User:
    """Create a user and attach the given seeded roles (flush only)."""
    user = User(
        email=email,
        password_hash=hash_password(password),
        full_name=full_name,
        phone=phone,
    )
    db.add(user)
    db.flush()
    for role_name in roles:
        role = db.scalar(select(Role).where(Role.role_name == role_name))
        if role is None:
            raise ValueError(f"role not seeded in roles table: {role_name}")
        db.add(UserRole(user_id=user.user_id, role_id=role.role_id))
    db.flush()
    return user


def set_last_login(db: Session, user: User) -> None:
    user.last_login_at = datetime.now(timezone.utc)
    db.flush()


def lock_account(db: Session, user: User, minutes: int) -> None:
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    db.flush()


def clear_lock(db: Session, user: User) -> None:
    if user.locked_until is not None:
        user.locked_until = None
        db.flush()


def anonymise(db: Session, user: User) -> None:
    """POPIA account deletion: strip all personal fields, keep the row as a
    tombstone so historical FKs (reports, reviews, assessments) stay intact.
    The account can never log in again (random password + DELETED status)."""
    user.email = f"deleted-{user.user_id}@anonymised.invalid"
    user.full_name = None
    user.phone = None
    user.password_hash = hash_password(secrets.token_urlsafe(32))
    user.status = UserStatus.DELETED
    user.locked_until = None
    db.flush()
