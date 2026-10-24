"""Education centre - public reading for everyone, admin content management."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..core.deps import client_ip, require_admin
from ..core.security import hash_ip
from ..db.session import get_db
from ..models.educational_resource import EducationalResource
from ..models.enums import AuditAction, EducationTopic
from ..models.user import User
from ..repositories import audit as audit_repo
from ..repositories import education as education_repo
from ..schemas.common import Page
from ..schemas.education import ResourceCreate, ResourceOut, ResourceUpdate

router = APIRouter(prefix="/api/v1/education", tags=["education"])


@router.get("", response_model=Page[ResourceOut])
def list_resources(
    topic: EducationTopic | None = None,
    language: str = Query(default="en", pattern=r"^[a-z]{2}(-[A-Z]{2})?$"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Public, published articles only (multi-language ready, Module 6)."""
    items, total = education_repo.list_published(
        db, topic=topic, language=language, limit=limit, offset=offset
    )
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/{slug}", response_model=ResourceOut)
def get_resource(slug: str, db: Session = Depends(get_db)) -> EducationalResource:
    resource = education_repo.get_by_slug(db, slug)
    if resource is None or not resource.is_published:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource


@router.post("", response_model=ResourceOut, status_code=201)
def create_resource(
    payload: ResourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> EducationalResource:
    slug = education_repo.unique_slug(
        db, payload.slug or education_repo.slugify(payload.title, payload.language)
    )
    links = (
        [{"label": link.label, "url": str(link.url)} for link in payload.official_links]
        if payload.official_links is not None
        else None
    )
    resource = education_repo.create(
        db,
        title=payload.title,
        slug=slug,
        topic=payload.topic,
        summary=payload.summary,
        content=payload.content,
        language=payload.language,
        official_links=links,
        display_order=payload.display_order,
        is_published=payload.is_published,
        created_by=admin.user_id,
    )
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.CREATE,
        entity_type="educational_resource",
        entity_id=resource.resource_id,
        details={"slug": slug},
        ip_hash=hash_ip(client_ip(request)),
    )
    db.commit()
    db.refresh(resource)
    return resource


@router.patch("/{resource_id}", response_model=ResourceOut)
def update_resource(
    resource_id: int,
    payload: ResourceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> EducationalResource:
    resource = education_repo.get(db, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="Resource not found")

    updates: dict = {}
    for field in ("title", "topic", "summary", "content", "display_order", "is_published"):
        value = getattr(payload, field)
        if value is not None:
            updates[field] = value
    if payload.official_links is not None:
        updates["official_links"] = [
            {"label": link.label, "url": str(link.url)} for link in payload.official_links
        ]

    resource = education_repo.update(db, resource, updates)
    audit_repo.write(
        db,
        actor_user_id=admin.user_id,
        action=AuditAction.UPDATE,
        entity_type="educational_resource",
        entity_id=resource.resource_id,
        details={"fields": sorted(updates)},
        ip_hash=hash_ip(client_ip(request)),
    )
    db.commit()
    db.refresh(resource)
    return resource
