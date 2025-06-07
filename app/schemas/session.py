from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class SessionInfo(BaseModel):
    """Schema for session information."""

    id: int
    user_agent: Optional[str]
    ip_address: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    country: Optional[str]
    city: Optional[str]
    is_current: bool = False  # Indicates if this is the current session

    class Config:
        from_attributes = True


class SessionListResponse(BaseModel):
    """Response for listing user sessions."""

    sessions: list[SessionInfo]
    total: int
    active: int


class SessionInvalidateResponse(BaseModel):
    """Response for session invalidation."""

    message: str
    invalidated_count: int
