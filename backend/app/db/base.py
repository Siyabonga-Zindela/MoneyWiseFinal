"""Declarative base. Models register themselves on import (see app/models/__init__.py)."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
