"""Scam report request/response shapes.

Two accepted payload shapes on POST /api/v1/reports:

1. Original JSON API shape:  title, description, channel, reported_url,
   reported_contact, occurred_at, assessment_id.
2. Frontend report-popup shape (field names exactly as the popup collects):
   phishing_type, message, risk_level ("high"/"medium"/"low"/"unsure"),
   date_received, sender, amount_asked, amount_promised (+ screenshot file
   via multipart/form-data - see routes/reports.py).

Both land in the same scam_reports row; the popup shape auto-derives the
missing API fields (title, description, channel) so nothing is lost.
"""

from datetime import date, datetime, timezone
from decimal import Decimal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..models.enums import ReportStatus, RiskCategoryDB, ScamChannel


def channel_from_phishing_type(phishing_type: str) -> ScamChannel:
    """Map the popup's free-text phishing type to the scam_channel enum."""
    value = phishing_type.casefold()
    if "sms" in value or "smishing" in value:
        return ScamChannel.SMS
    if "whatsapp" in value:
        return ScamChannel.WHATSAPP
    if "social" in value or "facebook" in value or "instagram" in value:
        return ScamChannel.SOCIAL_MEDIA
    if "email" in value:
        return ScamChannel.EMAIL
    if "website" in value or "link" in value or "url" in value:
        return ScamChannel.WEBSITE
    if "phone" in value or "vishing" in value or "call" in value:
        return ScamChannel.PHONE_CALL
    return ScamChannel.OTHER


RISK_LEVEL_ALIASES = {
    "high": RiskCategoryDB.HIGH,
    "medium": RiskCategoryDB.MEDIUM,
    "low": RiskCategoryDB.LOW,
    "unsure": RiskCategoryDB.INCONCLUSIVE,
    "not sure": RiskCategoryDB.INCONCLUSIVE,
}


class ReportCreate(BaseModel):
    # --- original API shape ---------------------------------------------------
    title: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    channel: ScamChannel | None = None
    reported_url: str | None = Field(default=None, max_length=2048)
    reported_contact: str | None = Field(
        default=None, max_length=255,
        description="Scammer phone/email/handle - never displayed publicly",
    )
    occurred_at: datetime | None = None

    # --- frontend report-popup shape (names match the popup inputs) -----------
    phishing_type: str | None = Field(default=None, max_length=120)
    message: str | None = Field(default=None, max_length=5000)
    risk_level: str | None = Field(
        default=None,
        description="high / medium / low / unsure (popup select)",
    )
    date_received: date | None = None
    sender: str | None = Field(
        default=None, max_length=255,
        description="Popup 'Sender identifier': phone/email/username/website",
    )
    amount_asked: Decimal | None = Field(default=None, ge=0, decimal_places=2)
    amount_promised: Decimal | None = Field(default=None, ge=0, decimal_places=2)
    assessment_id: int | None = Field(
        default=None,
        description="Optional link to the risk_assessments row created by /analysis",
    )

    @field_validator("risk_level")
    @classmethod
    def _normalise_risk_level(cls, value: str | None) -> str | None:
        if value is None:
            return None
        key = value.strip().casefold()
        if key not in RISK_LEVEL_ALIASES:
            raise ValueError("risk_level must be one of: high, medium, low, unsure")
        return key

    @field_validator("occurred_at")
    @classmethod
    def _not_in_future(cls, value: datetime | None) -> datetime | None:
        if value and value > datetime.now(timezone.utc):
            raise ValueError("occurred_at cannot be in the future")
        return value

    @model_validator(mode="after")
    def _merge_shapes(self) -> "ReportCreate":
        """Resolve the two payload shapes into one consistent record."""
        # description: popup sends `message`
        if self.description is None:
            self.description = self.message
        if not self.description or len(self.description.strip()) < 10:
            raise ValueError(
                "description (or message) is required - at least 10 characters"
            )
        # title: popup has none - derive from phishing_type or the message itself
        if self.title is None or not self.title.strip():
            source = self.phishing_type or " ".join(self.description.split()[:10])
            self.title = source.strip()[:200]
        # channel: derive from the popup's phishing type when not given explicitly
        if self.channel is None and self.phishing_type:
            self.channel = channel_from_phishing_type(self.phishing_type)
        # sender identifier + incident time from the popup fields
        if self.reported_contact is None and self.sender:
            self.reported_contact = self.sender.strip()[:255]
        if self.occurred_at is None and self.date_received is not None:
            self.occurred_at = datetime(
                self.date_received.year, self.date_received.month, self.date_received.day,
                tzinfo=timezone.utc,
            )
        # risk_level -> DB enum
        self._risk_level_db = RISK_LEVEL_ALIASES.get(self.risk_level) if self.risk_level else None
        return self

    @property
    def risk_level_db(self) -> RiskCategoryDB | None:
        return getattr(self, "_risk_level_db", None)


class VisibilityUpdate(BaseModel):
    """Admin-only report publish/unpublish (is_public defaults FALSE in DB)."""

    is_public: bool


class ReportOut(BaseModel):
    report_id: int
    reporter_id: int | None = None
    assessment_id: int | None = None
    title: str
    description: str
    channel: ScamChannel
    reported_url: str | None = None
    reported_contact: str | None = None
    occurred_at: datetime | None = None
    phishing_type: str | None = None
    risk_level: RiskCategoryDB | None = None
    amount_asked: Decimal | None = None
    amount_promised: Decimal | None = None
    screenshot_path: str | None = None
    duplicate_of_id: int | None = None
    status: ReportStatus
    is_public: bool
    created_at: datetime

    model_config = {"from_attributes": True}
