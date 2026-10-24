"""All ORM models for the user's backend half.

The risk engine tables (risk_assessments / assessment_evidence) now have
models too, so scam_reports.assessment_id is a real FK in metadata. Remaining
partner tables (FSCA, products, ...) still have NO models - do NOT run
`alembic revision --autogenerate`; write manual migrations instead.
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
    "User",
    "UserRole",
]
