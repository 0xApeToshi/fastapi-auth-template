from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func

from app.db.base import Base


class UserSession(Base):
    """
    User session model for tracking active sessions.
    Helps implement session management and concurrent session limits.
    """

    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # Session identification
    session_token = Column(
        String(255), unique=True, index=True, nullable=False
    )  # Hashed
    refresh_token = Column(Text, nullable=False)  # Hashed

    # Device/client information
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    fingerprint = Column(String(64), nullable=True)  # SHA256 hash

    # Session metadata
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_activity = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # Optional location data (can be populated based on IP)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        current_time = datetime.utcnow()
        expires_at = getattr(self, "expires_at")
        return bool(current_time > expires_at)

    def is_active(self) -> bool:
        """Check if the session is active (not expired)."""
        return not self.is_expired()
