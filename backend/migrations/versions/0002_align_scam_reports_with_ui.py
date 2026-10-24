"""align scam_reports with the UI report form (popup fields)

Adds the columns the MoneyWise frontend report popup collects:
  - phishing_type   (free text w/ datalist, e.g. "SMS phishing (smishing)")
  - risk_level      (high / medium / low / unsure -> risk_category enum, unsure = INCONCLUSIVE)
  - amount_asked    (Rands, the "Amount asked for" input)
  - amount_promised (Rands, the "Amount promised" input)
  - screenshot_path (stored upload path; PNG/JPG, max 5 MB enforced at the API layer)

The existing workflow columns (status, is_public, duplicate_of_id, reviews,
audit trail) are untouched - the UI fields are purely additive so the admin
review pipeline keeps working exactly as before.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-24
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scam_reports", sa.Column("phishing_type", sa.String(120), nullable=True))
    op.add_column(
        "scam_reports",
        sa.Column("risk_level", sa.Enum(name="risk_category", native_enum=True), nullable=True),
    )
    op.add_column("scam_reports", sa.Column("amount_asked", sa.Numeric(14, 2), nullable=True))
    op.add_column("scam_reports", sa.Column("amount_promised", sa.Numeric(14, 2), nullable=True))
    op.add_column("scam_reports", sa.Column("screenshot_path", sa.String(500), nullable=True))

    op.create_check_constraint(
        "scam_reports_amount_asked_non_negative",
        "scam_reports",
        "amount_asked IS NULL OR amount_asked >= 0",
    )
    op.create_check_constraint(
        "scam_reports_amount_promised_non_negative",
        "scam_reports",
        "amount_promised IS NULL OR amount_promised >= 0",
    )
    op.create_index(
        "idx_reports_risk_level", "scam_reports", ["risk_level"], postgresql_where=sa.text("risk_level IS NOT NULL")
    )


def downgrade() -> None:
    op.drop_index("idx_reports_risk_level", table_name="scam_reports")
    op.drop_constraint("scam_reports_amount_promised_non_negative", "scam_reports", type_="check")
    op.drop_constraint("scam_reports_amount_asked_non_negative", "scam_reports", type_="check")
    op.drop_column("scam_reports", "screenshot_path")
    op.drop_column("scam_reports", "amount_promised")
    op.drop_column("scam_reports", "amount_asked")
    op.drop_column("scam_reports", "risk_level")
    op.drop_column("scam_reports", "phishing_type")
