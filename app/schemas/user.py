from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import UserRole


class UserBase(BaseModel):
    """Base schema for user data."""

    email: EmailStr
    is_active: Optional[bool] = True
    role: Optional[UserRole] = UserRole.REGULAR


class UserCreate(UserBase):
    """Schema for user creation."""

    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        # Add password strength validation here if needed
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserUpdate(BaseModel):
    """Schema for user update."""

    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None
    password: Optional[str] = Field(None, min_length=8)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserInDBBase(UserBase):
    """Base schema for user in DB."""

    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class User(UserInDBBase):
    """Schema for user response without sensitive data."""

    pass


class UserInDB(UserInDBBase):
    """Schema for user in DB with password hash."""

    hashed_password: str
    refresh_token: Optional[str] = None
    refresh_token_expires_at: Optional[datetime] = None
