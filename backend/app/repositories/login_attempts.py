"""login_attempts data access - security telemetry for brute-force protection."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.login_attempt import LoginAttempt


def record(
    db: Session,
    email_attempted: str | None,
    success: bool,
    user_id: int | None = None,
    ip_hash: str | None = None,
    failure_reason: str | None = None,
) -> None:
    db.add(
        LoginAttempt(
            email_attempted=email_attempted,
            user_id=user_id,
            ip_hash=ip_hash,
            success=success,
            failure_reason=failure_reason,
        )
    )
    db.flush()


def count_recent_failures(db: Session, email: str, window_minutes: int) -> int:
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    stmt = (
        select(func.count())
        .select_from(LoginAttempt)
        .where(
            LoginAttempt.email_attempted == email,
            LoginAttempt.success.is_(False),
            LoginAttempt.attempted_at >= since,
        )
    )
    return db.scalar(stmt) or 0
