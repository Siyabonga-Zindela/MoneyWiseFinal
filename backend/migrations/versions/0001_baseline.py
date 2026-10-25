"""baseline: the 19-table Neon schema (001_baseline.sql v1.1)

Revision ID: 0001
Revises:
Create Date: 2026-10-24

v1.1 (2026-10-25): fsca_provider_records, fsca_warnings,
fsca_verification_checks and financial_products were REMOVED from the product
by owner decision and dropped from the live database. This baseline never
re-creates them. product_providers.fsca_record_id and
assessment_product_matches.product_id remain as plain BIGINT columns (no FK).

IMPORTANT - two ways to use this revision:

1. LIVE NEON DATABASE (already built manually from the baseline script):
       alembic stamp head
   This only records the revision in alembic_version. It must NOT be upgraded.

2. FRESH DATABASES (new Neon branches, CI, teammates' local Docker Postgres):
       alembic upgrade head
   This revision executes the full idempotent baseline SQL file (schema +
   clearly-labelled demo seed), so a fresh environment ends up identical.

WARNING: do NOT run `alembic revision --autogenerate` - five catalogue tables
(scam_indicators, user_financial_preferences, pre_payment_checks,
product_providers, assessment_product_matches) intentionally have NO ORM
models, so autogenerate would emit DROP statements for them. Write manual
migrations instead.

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
    "product_providers",
    "scam_indicators",
    "roles",
    "users",
]

ENUMS = [
    "assessment_source", "assessment_type", "audit_action", "education_topic",
    "income_range", "indicator_category", "indicator_severity",
    "pre_payment_action", "privacy_request_status", "privacy_request_type",
    "report_status", "review_action", "risk_category", "risk_profile",
    "scam_channel", "user_status",
]


def upgrade() -> None:
    op.execute(BASELINE_SQL.read_text(encoding="utf-8"))


def downgrade() -> None:
    for table in TABLES:
        op.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE')
    for enum_type in ENUMS:
        op.execute(f'DROP TYPE IF EXISTS "{enum_type}"')
