"""baseline: the 21-table Neon schema (scam_protection_neon_baseline.sql)

Revision ID: 0001
Revises:
Create Date: 2026-10-24

IMPORTANT - two ways to use this revision:

1. LIVE NEON DATABASE (already built manually from the baseline script):
       alembic stamp head
   This only records the revision in alembic_version. It must NOT be upgraded.

2. FRESH DATABASES (new Neon branches, CI, teammates' local Docker Postgres):
       alembic upgrade head
   This revision executes the full idempotent baseline SQL file (schema +
   clearly-labelled demo seed), so a fresh environment ends up identical.

WARNING: do NOT run `alembic revision --autogenerate` until the partner's
11 tables also exist as models (see backend/app/models/__init__.py) -
autogenerate would emit DROP statements for tables missing from the metadata.
Write manual migrations instead.

Revision ID: 0001
"""

from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

BASELINE_SQL = (
    Path(__file__).resolve().parents[2] / "db" / "baseline" / "001_baseline.sql"
)

TABLES = [
    "assessment_product_matches",
    "assessment_evidence",
    "fsca_verification_checks",
    "scam_report_reviews",
    "pre_payment_checks",
    "user_privacy_requests",
    "login_attempts",
    "refresh_tokens",
    "user_financial_preferences",
    "user_roles",
    "scam_reports",
    "risk_assessments",
    "educational_resources",
    "audit_logs",
    "financial_products",
    "product_providers",
    "fsca_warnings",
    "scam_indicators",
    "fsca_provider_records",
    "roles",
    "users",
]

ENUMS = [
    "assessment_source", "assessment_type", "audit_action", "education_topic",
    "fsca_check_outcome", "income_range", "indicator_category", "indicator_severity",
    "investment_timeframe", "pre_payment_action", "privacy_request_status",
    "privacy_request_type", "product_category", "report_status", "review_action",
    "risk_category", "risk_profile", "scam_channel", "user_status", "warning_type",
]


def upgrade() -> None:
    op.execute(BASELINE_SQL.read_text(encoding="utf-8"))


def downgrade() -> None:
    for table in TABLES:
        op.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE')
    for enum_type in ENUMS:
        op.execute(f'DROP TYPE IF EXISTS "{enum_type}"')
