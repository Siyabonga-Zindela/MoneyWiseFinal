"""Python enums mirroring the PostgreSQL enum types created by the baseline script.

Member values MUST equal the DB enum labels exactly (uppercase) - the DB types
already exist on Neon, so SQLAlchemy must emit compatible literals only.
"""

import enum

from sqlalchemy import Enum as SAEnum


def pg_enum(py_enum: type[enum.Enum], name: str) -> SAEnum:
    """SQLAlchemy Enum bound to the existing native PG type `name`."""
    return SAEnum(
        py_enum,
        name=name,
        native_enum=True,
        validate_strings=True,
        values_callable=lambda e: [m.value for m in e],
    )


class UserStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DELETED = "DELETED"


class ReportStatus(str, enum.Enum):
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REQUIRES_INVESTIGATION = "REQUIRES_INVESTIGATION"


class ReviewAction(str, enum.Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REQUIRES_INVESTIGATION = "REQUIRES_INVESTIGATION"


class ScamChannel(str, enum.Enum):
    SMS = "SMS"
    WHATSAPP = "WHATSAPP"
    EMAIL = "EMAIL"
    WEBSITE = "WEBSITE"
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    PHONE_CALL = "PHONE_CALL"
    IN_PERSON = "IN_PERSON"
    OTHER = "OTHER"


class AssessmentType(str, enum.Enum):
    SCAM_CONTENT = "SCAM_CONTENT"
    INVESTMENT_OFFER = "INVESTMENT_OFFER"
    PYRAMID_PONZI = "PYRAMID_PONZI"
    PRE_PAYMENT = "PRE_PAYMENT"


class AssessmentSource(str, enum.Enum):
    BASELINE_ENGINE = "BASELINE_ENGINE"
    NVIDIA_AI = "NVIDIA_AI"
    HYBRID = "HYBRID"
    MANUAL = "MANUAL"


class RiskCategoryDB(str, enum.Enum):
    """Uppercase mirror of the DB `risk_category` enum (risk_assessments / scam_reports.risk_level)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    INCONCLUSIVE = "INCONCLUSIVE"


class EducationTopic(str, enum.Enum):
    PYRAMID_SCHEMES = "PYRAMID_SCHEMES"
    PONZI_SCHEMES = "PONZI_SCHEMES"
    INVESTMENT_PROMISES = "INVESTMENT_PROMISES"
    PROVIDER_VERIFICATION = "PROVIDER_VERIFICATION"
    IMPERSONATION = "IMPERSONATION"
    RISK_AND_LIQUIDITY = "RISK_AND_LIQUIDITY"
    CREDENTIAL_SAFETY = "CREDENTIAL_SAFETY"
    AFTER_A_SCAM = "AFTER_A_SCAM"
    OTHER = "OTHER"


class PrivacyRequestType(str, enum.Enum):
    ACCOUNT_DELETION = "ACCOUNT_DELETION"
    DATA_EXPORT = "DATA_EXPORT"
    DATA_CORRECTION = "DATA_CORRECTION"
    MARKETING_OPT_OUT = "MARKETING_OPT_OUT"


class PrivacyRequestStatus(str, enum.Enum):
    RECEIVED = "RECEIVED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    REJECTED = "REJECTED"


class AuditAction(str, enum.Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    STATUS_CHANGE = "STATUS_CHANGE"
    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    EXPORT = "EXPORT"
