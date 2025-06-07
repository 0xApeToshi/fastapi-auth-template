import enum
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String, Text
from sqlalchemy.sql import func

from app.db.base import Base


class UserRole(str, enum.Enum):
    """User role enumeration."""

    ADMIN = "admin"
    REGULAR = "regular"


class User(Base):
    """User model in the database."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role: Column[UserRole] = Column(
        Enum(UserRole), default=UserRole.REGULAR, nullable=False
    )

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Fields for refresh token management
    refresh_token = Column(Text, nullable=True)
    refresh_token_expires_at = Column(DateTime(timezone=True), nullable=True)

    # Password reset fields
    password_reset_code = Column(String(255), nullable=True)  # Hashed 6-digit code
    password_reset_expires_at = Column(DateTime(timezone=True), nullable=True)
    password_reset_attempts = Column(Integer, default=0, nullable=False)

    # Account security fields
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_attempt = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    def is_locked(self) -> bool:
        """Check if the account is currently locked."""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False


class BlacklistedToken(Base):
    """
    Blacklisted token model for logout functionality.
    Stores revoked tokens until they expire.
    """

    __tablename__ = "blacklisted_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=True)  # For mass invalidation
    blacklisted_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    reason = Column(
        String(50), nullable=True
    )  # 'logout', 'refresh', 'rotation_detected', 'session_limit', 'security'


class TokenBlacklistReason(str, enum.Enum):
    """Reasons for token blacklisting."""

    LOGOUT = "logout"
    REFRESH = "refresh"
    ROTATION_DETECTED = "rotation_detected"
    SESSION_LIMIT = "session_limit"
    SECURITY = "security"
    PASSWORD_RESET = "password_reset"
