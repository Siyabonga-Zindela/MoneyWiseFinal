"""Stakeholder + investment-offer shapes.

The admin-users screen (users.js) and the external-stakeholder screen
(externalStakeholder.js) speak a UI dialect (org_type keys like 'bank',
statuses like 'invited'); these models accept and return exactly that so the
JS needs no translation layer.
"""

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, EmailStr, Field, field_validator

ORG_TYPES = ("bank", "telco", "regulator", "police", "consumer", "other")
ACCESS_LEVELS = ("view", "review")
ALERT_PREFS = ("none", "high", "all")


class StakeholderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    email: EmailStr
    organisation: str = Field(min_length=1, max_length=150)
    org_type: str = Field(default="other")
    access: str = Field(default="view")
    alerts: str = Field(default="none")

    @field_validator("email")
    @classmethod
    def _lower_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("org_type")
    @classmethod
    def _org_type(cls, value: str) -> str:
        if value not in ORG_TYPES:
            raise ValueError(f"org_type must be one of {', '.join(ORG_TYPES)}")
        return value

    @field_validator("access")
    @classmethod
    def _access(cls, value: str) -> str:
        if value not in ACCESS_LEVELS:
            raise ValueError(f"access must be one of {', '.join(ACCESS_LEVELS)}")
        return value

    @field_validator("alerts")
    @classmethod
    def _alerts(cls, value: str) -> str:
        if value not in ALERT_PREFS:
            raise ValueError(f"alerts must be one of {', '.join(ALERT_PREFS)}")
        return value


class StakeholderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    organisation: str | None = Field(default=None, min_length=1, max_length=150)
    org_type: str | None = None
    access: str | None = None
    alerts: str | None = None
    status: str | None = None  # 'suspended' | 'active' | 'invited' (reactivate)

    @field_validator("org_type")
    @classmethod
    def _org_type(cls, value: str | None) -> str | None:
        if value is not None and value not in ORG_TYPES:
            raise ValueError(f"org_type must be one of {', '.join(ORG_TYPES)}")
        return value

    @field_validator("access")
    @classmethod
    def _access(cls, value: str | None) -> str | None:
        if value is not None and value not in ACCESS_LEVELS:
            raise ValueError(f"access must be one of {', '.join(ACCESS_LEVELS)}")
        return value

    @field_validator("alerts")
    @classmethod
    def _alerts(cls, value: str | None) -> str | None:
        if value is not None and value not in ALERT_PREFS:
            raise ValueError(f"alerts must be one of {', '.join(ALERT_PREFS)}")
        return value


class StakeholderOut(BaseModel):
    id: int
    name: str
    email: str
    organisation: str
    org_type: str
    access: str
    alerts: str
    status: str  # 'active' | 'invited' | 'suspended' (UI dialect)
    last_active: str | None = None
    temporary_password: str | None = Field(
        default=None,
        description="Shown ONCE on create/resend while no mail provider is wired.",
    )


class AdminSummary(BaseModel):
    new_reports: int


class OfferCreate(BaseModel):
    product_name: str = Field(min_length=1, max_length=150)
    product_category: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=5000)
    min_investment: Decimal = Field(ge=0)
    max_investment: Decimal = Field(ge=0)
    fees_summary: str | None = Field(default=None, max_length=5000)
    indicative_return_range: str | None = Field(default=None, max_length=120)
    access_condition: str | None = Field(default=None, max_length=300)
    material_risk: str | None = Field(default=None, max_length=5000)
    suitable_timeframe: str | None = Field(default=None, max_length=120)
    url: str | None = Field(default=None, max_length=500)

    @field_validator("max_investment")
    @classmethod
    def _min_max(cls, value: Decimal, info):
        minimum = info.data.get("min_investment")
        if minimum is not None and value < minimum:
            raise ValueError("max_investment must be at least min_investment")
        return value


class OfferUpdate(BaseModel):
    """Only the columns a partner may change after an offer exists."""

    min_investment: Decimal | None = Field(default=None, ge=0)
    max_investment: Decimal | None = Field(default=None, ge=0)
    indicative_return_range: str | None = Field(default=None, max_length=120)


class OfferOut(BaseModel):
    id: int = Field(validation_alias="offer_id")  # ORM attr is offer_id
    product_name: str
    product_category: str
    description: str
    currency: str
    min_investment: Decimal
    max_investment: Decimal
    fees_summary: str | None = None
    indicative_return_range: str | None = None
    access_condition: str | None = None
    material_risk: str | None = None
    suitable_timeframe: str | None = None
    url: str | None = None
    updated_at: datetime

    model_config = {"from_attributes": True}
