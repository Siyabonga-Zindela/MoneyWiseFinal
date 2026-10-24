"""educational_resources table - learning hub content (Module 6)."""

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Identity, SmallInteger, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base
from .enums import EducationTopic, pg_enum


class EducationalResource(Base):
    __tablename__ = "educational_resources"

    resource_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(220), nullable=False, unique=True)
    topic: Mapped[EducationTopic] = mapped_column(
        pg_enum(EducationTopic, "education_topic"), nullable=False
    )
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(
        String(10), nullable=False, server_default=text("'en'")
    )
    official_links: Mapped[list | None] = mapped_column(JSONB)
    display_order: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    is_published: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
