"""refresh_tokens data access - only SHA-256 hashes touch the database."""

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..core.security import sha256_hex
from ..models.refresh_token import RefreshToken


def store(
    db: Session,
    user_id: int,
    token: str,
    expires_at: datetime,
    user_agent: str | None = None,
    ip_hash: str | None = None,
) -> RefreshToken:
    row = RefreshToken(
        user_id=user_id,
        token_hash=sha256_hex(token),
        expires_at=expires_at,
        user_agent=user_agent[:255] if user_agent else None,
        ip_hash=ip_hash,
    )
    db.add(row)
    db.flush()
    return row


def get_active_by_hash(db: Session, token: str) -> RefreshToken | None:
    row = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(token))
    )
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at <= datetime.now(timezone.utc):
        return None
    return row


def revoke(db: Session, row: RefreshToken) -> None:
    row.revoked_at = datetime.now(timezone.utc)
    db.flush()


def revoke_all_for_user(db: Session, user_id: int) -> int:
    result = db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    db.flush()
    return result.rowcount or 0
