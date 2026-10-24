"""POPIA privacy request shapes."""

from datetime import datetime

from pydantic import BaseModel, Field

from ..models.enums import PrivacyRequestStatus, PrivacyRequestType


class PrivacyRequestCreate(BaseModel):
    request_type: PrivacyRequestType
    details: str | None = Field(default=None, max_length=4000)


class PrivacyProcessRequest(BaseModel):
    status: PrivacyRequestStatus
    retention_note: str | None = Field(
        default=None, max_length=4000,
        description="Why some data was retained (legal obligation), if applicable",
    )


class PrivacyRequestOut(BaseModel):
    request_id: int
    user_id: int | None = None
    request_type: PrivacyRequestType
    status: PrivacyRequestStatus
    details: str | None = None
    retention_note: str | None = None
    requested_at: datetime
    completed_at: datetime | None = None
    processed_by: int | None = None

    model_config = {"from_attributes": True}
