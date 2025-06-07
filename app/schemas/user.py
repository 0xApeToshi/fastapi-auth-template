import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import UserRole


class UserBase(BaseModel):
    """Base schema for user data."""

    email: EmailStr
    is_active: Optional[bool] = True
    role: Optional[UserRole] = UserRole.REGULAR


class UserCreate(UserBase):
    """Schema for user creation."""

    password: str = Field(..., min_length=12)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Validate password strength according to security best practices.

        Requirements:
        - At least 12 characters long
        - Contains lowercase letters
        - Contains uppercase letters
        - Contains numbers
        - Contains special characters
        - No common weak patterns
        """
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")

        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")

        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")

        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")

        # # Check for common weak patterns
        # common_patterns = [
        #     r"123456",
        #     r"password",
        #     r"qwerty",
        #     r"admin",
        #     r"letmein",
        #     r"welcome",
        #     r"monkey",
        #     r"dragon",
        #     r"master",
        #     r"login",
        # ]

        # for pattern in common_patterns:
        #     if re.search(pattern, v, re.IGNORECASE):
        #         raise ValueError("Password contains common weak patterns")

        return v


class UserUpdate(BaseModel):
    """Schema for user update."""

    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None
    password: Optional[str] = Field(None, min_length=12)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate password strength for updates.
        Same validation as UserCreate but optional.
        """
        if v is None:
            return v

        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")

        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")

        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")

        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")

        # Check for common weak patterns
        common_patterns = [
            r"123456",
            r"password",
            r"qwerty",
            r"admin",
            r"letmein",
            r"welcome",
            r"monkey",
            r"dragon",
            r"master",
            r"login",
        ]

        for pattern in common_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("Password contains common weak patterns")

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


class UserWithLoginAttempts(UserInDBBase):
    """Schema for user with login attempt tracking (for future MFA support)."""

    failed_login_attempts: Optional[int] = 0
    locked_until: Optional[datetime] = None
    last_login_at: Optional[datetime] = None

    def is_locked(self) -> bool:
        """Check if user account is currently locked."""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
