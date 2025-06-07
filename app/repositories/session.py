from datetime import datetime
from typing import List, Optional

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_refresh_token, verify_refresh_token
from app.models.session import UserSession


class SessionRepository:
    """Repository for user session operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        user_id: int,
        session_token: str,
        refresh_token: str,
        user_agent: Optional[str],
        ip_address: Optional[str],
        fingerprint: Optional[str],
        expires_at: datetime,
    ) -> UserSession:
        """
        Create a new user session.

        FIXED: Only hash tokens once here, not in the service layer.

        Args:
            user_id: User ID
            session_token: Raw session identifier (will be hashed here)
            refresh_token: Raw refresh token (will be hashed here)
            user_agent: Client user agent
            ip_address: Client IP address
            fingerprint: Client fingerprint
            expires_at: Session expiration time

        Returns:
            Created UserSession
        """
        # Hash tokens before storing - this is the ONLY place they should be hashed
        session_token_hash = hash_refresh_token(session_token)
        refresh_token_hash = hash_refresh_token(refresh_token)

        session = UserSession(
            user_id=user_id,
            session_token=session_token_hash,  # Hashed once here
            refresh_token=refresh_token_hash,  # Hashed once here
            user_agent=user_agent,
            ip_address=ip_address,
            fingerprint=fingerprint,
            expires_at=expires_at,
        )

        self.db.add(session)
        await self.db.flush()
        await self.db.refresh(session)
        return session

    async def get_by_session_token(
        self, user_id: int, session_token: str
    ) -> Optional[UserSession]:
        """
        Get session by session token.

        FIXED: Properly hash the raw token for comparison.

        Args:
            user_id: User ID
            session_token: Raw session token to verify

        Returns:
            UserSession if found and valid
        """
        # Hash the raw token for comparison with stored hash
        session_token_hash = hash_refresh_token(session_token)

        result = await self.db.execute(
            select(UserSession).where(
                UserSession.user_id == user_id,
                UserSession.session_token == session_token_hash,
            )
        )
        return result.scalars().first()

    async def get_user_sessions(
        self, user_id: int, only_active: bool = False
    ) -> List[UserSession]:
        """
        Get all sessions for a user.

        Args:
            user_id: User ID
            only_active: If True, only return non-expired sessions

        Returns:
            List of UserSession objects
        """
        query = select(UserSession).where(UserSession.user_id == user_id)

        if only_active:
            query = query.where(UserSession.expires_at > datetime.utcnow())

        query = query.order_by(UserSession.last_activity.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count_active_sessions(self, user_id: int) -> int:
        """
        Count active (non-expired) sessions for a user.

        Args:
            user_id: User ID

        Returns:
            Number of active sessions
        """
        result = await self.db.execute(
            select(UserSession).where(
                UserSession.user_id == user_id,
                UserSession.expires_at > datetime.utcnow(),
            )
        )
        return len(result.scalars().all())

    async def update_activity(self, session_id: int) -> bool:
        """
        Update last activity timestamp for a session.

        Args:
            session_id: Session ID

        Returns:
            True if updated successfully
        """
        stmt = (
            update(UserSession)
            .where(UserSession.id == session_id)
            .values(last_activity=datetime.utcnow())
        )
        result = await self.db.execute(stmt)
        return result.rowcount > 0

    async def verify_refresh_token(self, session_id: int, refresh_token: str) -> bool:
        """
        Verify a refresh token against the session.

        FIXED: Properly verify raw token against stored hash.

        Args:
            session_id: Session ID
            refresh_token: Raw refresh token to verify

        Returns:
            True if token is valid
        """
        result = await self.db.execute(
            select(UserSession).where(UserSession.id == session_id)
        )
        session = result.scalars().first()

        if not session:
            return False

        # Verify raw token against stored hash
        stored_refresh_token = str(session.refresh_token)
        return verify_refresh_token(refresh_token, stored_refresh_token)

    async def delete_session(self, session_id: int) -> bool:
        """
        Delete a specific session.

        Args:
            session_id: Session ID

        Returns:
            True if deleted successfully
        """
        stmt = delete(UserSession).where(UserSession.id == session_id)
        result = await self.db.execute(stmt)
        return result.rowcount > 0

    async def delete_user_sessions(
        self, user_id: int, except_session_id: Optional[int] = None
    ) -> int:
        """
        Delete all sessions for a user, optionally keeping one.

        Args:
            user_id: User ID
            except_session_id: Session ID to keep (optional)

        Returns:
            Number of deleted sessions
        """
        stmt = delete(UserSession).where(UserSession.user_id == user_id)

        if except_session_id:
            stmt = stmt.where(UserSession.id != except_session_id)

        result = await self.db.execute(stmt)
        return result.rowcount or 0

    async def delete_expired_sessions(self) -> int:
        """
        Delete all expired sessions.

        Returns:
            Number of deleted sessions
        """
        stmt = delete(UserSession).where(UserSession.expires_at < datetime.utcnow())
        result = await self.db.execute(stmt)
        return result.rowcount or 0

    async def get_oldest_active_session(self, user_id: int) -> Optional[UserSession]:
        """
        Get the oldest active session for a user.

        Args:
            user_id: User ID

        Returns:
            Oldest active UserSession or None
        """
        result = await self.db.execute(
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.expires_at > datetime.utcnow(),
            )
            .order_by(UserSession.created_at.asc())
            .limit(1)
        )
        return result.scalars().first()
