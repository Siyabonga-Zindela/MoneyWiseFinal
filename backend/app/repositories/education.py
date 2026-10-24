"""educational_resources data access (Module 6 learning hub)."""

import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.educational_resource import EducationalResource
from ..models.enums import EducationTopic


def get(db: Session, resource_id: int) -> EducationalResource | None:
    return db.get(EducationalResource, resource_id)


def get_by_slug(db: Session, slug: str) -> EducationalResource | None:
    return db.scalar(
        select(EducationalResource).where(EducationalResource.slug == slug)
    )


def list_published(
    db: Session,
    topic: EducationTopic | None = None,
    language: str = "en",
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[EducationalResource], int]:
    base = select(EducationalResource).where(
        EducationalResource.is_published.is_(True),
        EducationalResource.language == language,
    )
    if topic is not None:
        base = base.where(EducationalResource.topic == topic)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    items = list(
        db.scalars(
            base.order_by(
                EducationalResource.display_order.asc(),
                EducationalResource.created_at.desc(),
            )
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return items, total


def slugify(title: str, language: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:180]
    return f"{slug or 'resource'}-{language}"


def unique_slug(db: Session, base_slug: str) -> str:
    """Append -2, -3, ... until the slug is free."""
    candidate = base_slug
    counter = 2
    while db.scalar(
        select(EducationalResource.resource_id).where(
            EducationalResource.slug == candidate
        )
    ):
        candidate = f"{base_slug}-{counter}"
        counter += 1
    return candidate


def create(db: Session, **fields) -> EducationalResource:
    resource = EducationalResource(**fields)
    db.add(resource)
    db.flush()
    return resource


def update(db: Session, resource: EducationalResource, fields: dict) -> EducationalResource:
    for key, value in fields.items():
        setattr(resource, key, value)
    db.flush()
    return resource
