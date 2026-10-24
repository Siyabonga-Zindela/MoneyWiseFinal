"""Auth request/response shapes."""

import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    # bcrypt only uses the first 72 bytes; 64 chars keeps it well inside that.
    password: str = Field(min_length=8, max_length=64)
    full_name: str | None = Field(default=None, max_length=150)
    phone: str | None = Field(default=None, max_length=32)

    @field_validator("email")
    @classmethod
    def _lower_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("password")
    @classmethod
    def _strong_password(cls, value: str) -> str:
        if not re.search(r"[A-Z]", value):
            raise ValueError("password needs at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("password needs at least one lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("password needs at least one digit")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _lower_email(cls, value: str) -> str:
        return value.strip().lower()


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=2000)


class LogoutRequest(BaseModel):
    refresh_token: str | None = None  # None => revoke ALL my sessions


class UserOut(BaseModel):
    user_id: int
    email: str
    full_name: str | None = None
    phone: str | None = None
    status: str
    roles: list[str] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # access-token lifetime in seconds
    user: UserOut
