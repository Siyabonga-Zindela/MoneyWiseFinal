"""Educational resource shapes (Module 6 learning hub)."""

from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl

from ..models.enums import EducationTopic


class OfficialLink(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    url: HttpUrl


class ResourceCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    slug: str | None = Field(
        default=None, max_length=220,
        description="Auto-generated from title + language when omitted",
    )
    topic: EducationTopic
    summary: str = Field(min_length=10, max_length=500)
    content: str = Field(min_length=20)
    language: str = Field(default="en", pattern=r"^[a-z]{2}(-[A-Z]{2})?$")
    official_links: list[OfficialLink] | None = None
    display_order: int = Field(default=0, ge=0, le=32767)
    is_published: bool = False


class ResourceUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    topic: EducationTopic | None = None
    summary: str | None = Field(default=None, min_length=10, max_length=500)
    content: str | None = Field(default=None, min_length=20)
    official_links: list[OfficialLink] | None = None
    display_order: int | None = Field(default=None, ge=0, le=32767)
    is_published: bool | None = None


class ResourceOut(BaseModel):
    resource_id: int
    title: str
    slug: str
    topic: EducationTopic
    summary: str
    content: str
    language: str
    official_links: list | None = None
    display_order: int
    is_published: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
