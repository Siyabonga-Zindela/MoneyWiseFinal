"""All ORM models for the user's backend half.

The risk engine tables (risk_assessments / assessment_evidence) now have
models too, so scam_reports.assessment_id is a real FK in metadata.

v1.1 (2026-10-25): the FSCA tables (fsca_provider_records, fsca_warnings,
fsca_verification_checks) and financial_products were REMOVED from the product
by owner decision - do NOT re-create them or add models for them.

Five catalogue tables intentionally have NO models (scam_indicators,
user_financial_preferences, pre_payment_checks, product_providers,
assessment_product_matches) - do NOT run `alembic revision --autogenerate`;
it would emit DROP statements for them. Write manual migrations instead.
"""

from .audit_log import AuditLog
from .educational_resource import EducationalResource
from .login_attempt import LoginAttempt
from .privacy_request import PrivacyRequest
from .refresh_token import RefreshToken
from .risk_assessment import AssessmentEvidence, RiskAssessment
from .role import Role
from .scam_report import ScamReport
from .scam_report_review import ScamReportReview
from .stakeholder import StakeholderOffer, StakeholderProfile
from .user import User
from .user_role import UserRole

__all__ = [
    "AssessmentEvidence",
    "AuditLog",
    "EducationalResource",
    "LoginAttempt",
    "PrivacyRequest",
    "RefreshToken",
    "RiskAssessment",
    "Role",
    "ScamReport",
    "ScamReportReview",
    "StakeholderOffer",
    "StakeholderProfile",
    "User",
    "UserRole",
]
