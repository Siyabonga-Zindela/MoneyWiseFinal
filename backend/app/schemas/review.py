"""Admin review shapes (one decision = one append-only row)."""

from datetime import datetime

from pydantic import BaseModel, Field

from ..models.enums import ReviewAction


class ReviewCreate(BaseModel):
    action: ReviewAction
    notes: str | None = Field(default=None, max_length=4000)


class ReviewOut(BaseModel):
    review_id: int
    report_id: int
    reviewer_id: int | None = None
    action: ReviewAction
    notes: str | None = None
    decided_at: datetime

    model_config = {"from_attributes": True}
