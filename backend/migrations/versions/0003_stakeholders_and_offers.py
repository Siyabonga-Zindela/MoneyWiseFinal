"""stakeholder profiles + investment offers + STAKEHOLDER role

Combines the System-Admin and External-Stakeholder UI pages with the backend:

  - roles: seed the STAKEHOLDER role (idempotent).
  - stakeholder_profiles: org metadata the admin-users screen manages
    (organisation, org_type, access level, alert preference, invitation
    state, last_active_at). One row per STAKEHOLDER user; the auth/lockout
    machinery on users is reused, not duplicated.
  - stakeholder_offers: the investment offers a partner stakeholder lists
    and keeps updated (externalStakeholder screen). Column names mirror the
    UI form fields exactly (min_investment, indicative_return_range, ...).

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-24
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. STAKEHOLDER role (roles table is seeded; keep idempotent).
    op.execute(
        "INSERT INTO roles (role_name, description) VALUES "
        "('STAKEHOLDER', 'External partner who lists investment offers and can be granted report visibility') "
        "ON CONFLICT (role_name) DO NOTHING"
    )

    # 2. Stakeholder org/profile metadata (1:1 with users).
    op.create_table(
        "stakeholder_profiles",
        sa.Column("stakeholder_id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id", sa.Integer(),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False, unique=True,
        ),
        sa.Column("organisation", sa.String(150), nullable=False),
        sa.Column("org_type", sa.String(20), nullable=False),
        sa.Column("access", sa.String(10), nullable=False, server_default="view"),
        sa.Column("alerts", sa.String(10), nullable=False, server_default="none"),
        sa.Column("invite_pending", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "org_type IN ('bank','telco','regulator','police','consumer','other')",
            name="stakeholder_profiles_org_type",
        ),
        sa.CheckConstraint(
            "access IN ('view','review')", name="stakeholder_profiles_access"
        ),
        sa.CheckConstraint(
            "alerts IN ('none','high','all')", name="stakeholder_profiles_alerts"
        ),
    )
    op.create_index(
        "idx_stakeholder_profiles_user", "stakeholder_profiles", ["user_id"], unique=True
    )

    # 3. Investment offers owned by stakeholder users.
    op.create_table(
        "stakeholder_offers",
        sa.Column("offer_id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id", sa.Integer(),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("product_name", sa.String(150), nullable=False),
        sa.Column("product_category", sa.String(80), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("currency", sa.String(8), nullable=False, server_default="ZAR"),
        sa.Column("min_investment", sa.Numeric(14, 2), nullable=False),
        sa.Column("max_investment", sa.Numeric(14, 2), nullable=False),
        sa.Column("fees_summary", sa.Text(), nullable=True),
        sa.Column("indicative_return_range", sa.String(120), nullable=True),
        sa.Column("access_condition", sa.String(300), nullable=True),
        sa.Column("material_risk", sa.Text(), nullable=True),
        sa.Column("suitable_timeframe", sa.String(120), nullable=True),
        sa.Column("url", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "max_investment >= min_investment", name="stakeholder_offers_min_max"
        ),
        sa.CheckConstraint(
            "min_investment >= 0 AND max_investment >= 0",
            name="stakeholder_offers_amounts_non_negative",
        ),
    )
    op.create_index("idx_stakeholder_offers_user", "stakeholder_offers", ["user_id"])


def downgrade() -> None:
    op.drop_index("idx_stakeholder_offers_user", table_name="stakeholder_offers")
    op.drop_table("stakeholder_offers")
    op.drop_index("idx_stakeholder_profiles_user", table_name="stakeholder_profiles")
    op.drop_table("stakeholder_profiles")
    op.execute(
        "DELETE FROM user_roles WHERE role_id IN "
        "(SELECT role_id FROM roles WHERE role_name = 'STAKEHOLDER')"
    )
    op.execute("DELETE FROM roles WHERE role_name = 'STAKEHOLDER'")
