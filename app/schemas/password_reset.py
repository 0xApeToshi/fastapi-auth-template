from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.user import UserCreate  # For password validation


class PasswordResetRequest(BaseModel):
    """Schema for requesting a password reset."""

    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Schema for confirming a password reset with PIN."""

    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    new_password: str = Field(..., min_length=12)

    @field_validator("code")
    @classmethod
    def validate_code_format(cls, v: str) -> str:
        """Validate that code is 6 digits."""
        if not v.isdigit() or len(v) != 6:
            raise ValueError("Code must be exactly 6 digits")
        return v

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Reuse password validation from UserCreate.
        This ensures consistent password requirements.
        """
        # Use the same validation logic as UserCreate
        UserCreate.validate_password_strength(v)
        return v


class PasswordResetResponse(BaseModel):
    """Response after requesting password reset."""

    message: str = "If the email exists, a reset code has been sent"
    # Note: We don't reveal if the email exists for security
