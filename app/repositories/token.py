from datetime import datetime
from typing import Optional, cast

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.user import BlacklistedToken, TokenBlacklistReason


class TokenRepository:
    """Repository for token management operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: JWT token to check

        Returns:
            True if token is blacklisted, False otherwise
        """
        result = await self.db.execute(
            select(BlacklistedToken).where(BlacklistedToken.token == token)
        )
        return result.scalars().first() is not None

    async def blacklist(
        self,
        token: str,
        expires_at: datetime,
        user_id: Optional[int] = None,
        reason: Optional[TokenBlacklistReason] = None,
    ) -> BlacklistedToken:
        """
        Add a token to blacklist.

        Args:
            token: JWT token to blacklist
            expires_at: Token expiration date
            user_id: Optional user ID for mass invalidation
            reason: Optional reason for blacklisting

        Returns:
            BlacklistedToken object
        """
        blacklisted_token = BlacklistedToken(
            token=token,
            expires_at=expires_at,
            user_id=user_id,
            reason=reason.value if reason else None,
        )
        self.db.add(blacklisted_token)
        await self.db.flush()
        return blacklisted_token

    async def invalidate_all_user_tokens(
        self, user_id: int, reason: TokenBlacklistReason
    ) -> int:
        """
        Invalidate all tokens for a specific user.
        This is used when suspicious activity is detected.

        Args:
            user_id: User ID whose tokens to invalidate
            reason: Reason for invalidation

        Returns:
            Number of tokens invalidated
        """
        # In a real implementation, you would:
        # 1. Get all active tokens for the user from sessions
        # 2. Add them to blacklist
        # 3. Clear user's refresh token
        # 4. Delete all user sessions

        # For now, we'll clear the user's refresh token
        from app.repositories.user import UserRepository

        user_repo = UserRepository(self.db)
        await user_repo.update_refresh_token(user_id, None, None)

        # Delete all user sessions
        from app.repositories.session import SessionRepository

        session_repo = SessionRepository(self.db)
        deleted_sessions = await session_repo.delete_user_sessions(user_id)

        return deleted_sessions

    async def clean_expired_tokens(self) -> int:
        """
        Remove expired tokens from blacklist.

        Returns:
            Number of removed tokens
        """
        now = datetime.utcnow()
        stmt = delete(BlacklistedToken).where(BlacklistedToken.expires_at < now)
        result = await self.db.execute(stmt)
        return result.rowcount or 0

    async def get_expired_token_count(self) -> int:
        """
        Get count of expired tokens that can be cleaned up.

        Returns:
            Number of expired tokens
        """
        now = datetime.utcnow()
        result = await self.db.execute(
            select(BlacklistedToken).where(BlacklistedToken.expires_at < now)
        )
        return len(result.scalars().all())

    async def check_token_reuse(self, token: str, user_id: int) -> bool:
        """
        Check if a refresh token has been reused (rotation detection).

        Args:
            token: Refresh token to check
            user_id: User ID

        Returns:
            True if token reuse is detected
        """
        # Check if token is blacklisted with 'refresh' reason
        result = await self.db.execute(
            select(BlacklistedToken).where(
                BlacklistedToken.token == token,
                BlacklistedToken.reason == TokenBlacklistReason.REFRESH.value,
            )
        )
        blacklisted = result.scalars().first()

        if blacklisted:
            # Token reuse detected!
            # Invalidate all user tokens as a security measure
            await self.invalidate_all_user_tokens(
                user_id, TokenBlacklistReason.ROTATION_DETECTED
            )
            return True

        return False


class TokenCleanupScheduler:
    """Scheduler for automatic token cleanup using APScheduler."""

    def __init__(self) -> None:
        self.scheduler: Optional[AsyncIOScheduler] = None
        self._is_running = False

    def start_scheduler(self, interval_hours: int = 1) -> None:
        """
        Start the token cleanup scheduler.

        Args:
            interval_hours: Cleanup interval in hours (default: 1 hour)
        """
        if self._is_running:
            return

        self.scheduler = AsyncIOScheduler()

        # Add the cleanup job
        self.scheduler.add_job(
            func=self._cleanup_expired_tokens,
            trigger=IntervalTrigger(hours=interval_hours),
            id="token_cleanup",
            name="Clean expired tokens",
            replace_existing=True,
            max_instances=1,  # Ensure only one cleanup runs at a time
        )

        # Add session cleanup job
        self.scheduler.add_job(
            func=self._cleanup_expired_sessions,
            trigger=IntervalTrigger(hours=interval_hours * 2),  # Less frequent
            id="session_cleanup",
            name="Clean expired sessions",
            replace_existing=True,
            max_instances=1,
        )

        self.scheduler.start()
        self._is_running = True
        print(f"Token cleanup scheduler started (interval: {interval_hours} hours)")

    def stop_scheduler(self) -> None:
        """Stop the token cleanup scheduler."""
        if self.scheduler and self._is_running:
            self.scheduler.shutdown()
            self._is_running = False
            print("Token cleanup scheduler stopped")

    async def _cleanup_expired_tokens(self) -> None:
        """
        Scheduled job to clean up expired tokens.
        This runs in its own database session.
        """
        try:
            async with AsyncSessionLocal() as session:
                token_repo = TokenRepository(session)

                # Get count before cleanup for logging
                expired_count = await token_repo.get_expired_token_count()

                if expired_count > 0:
                    cleaned = await token_repo.clean_expired_tokens()
                    await session.commit()
                    print(f"Scheduled cleanup: Removed {cleaned} expired tokens")
                else:
                    print("Scheduled cleanup: No expired tokens to clean")

        except Exception as e:
            print(f"Error during scheduled token cleanup: {e}")

    async def _cleanup_expired_sessions(self) -> None:
        """
        Scheduled job to clean up expired sessions.
        """
        try:
            async with AsyncSessionLocal() as session:
                from app.repositories.session import SessionRepository

                session_repo = SessionRepository(session)
                cleaned = await session_repo.delete_expired_sessions()
                await session.commit()
                print(f"Scheduled cleanup: Removed {cleaned} expired sessions")

        except Exception as e:
            print(f"Error during scheduled session cleanup: {e}")

    async def manual_cleanup(self) -> int:
        """
        Manually trigger token cleanup outside of the scheduled job.

        Returns:
            Number of tokens cleaned up
        """
        try:
            async with AsyncSessionLocal() as session:
                token_repo = TokenRepository(session)
                cleaned = await token_repo.clean_expired_tokens()
                await session.commit()
                print(f"Manual cleanup: Removed {cleaned} expired tokens")
                return cleaned
        except Exception as e:
            print(f"Error during manual token cleanup: {e}")
            return 0

    @property
    def is_running(self) -> bool:
        """Check if the scheduler is currently running."""
        return self._is_running and self.scheduler is not None

    def get_next_run_time(self) -> Optional[datetime]:
        """Get the next scheduled run time for token cleanup."""
        if self.scheduler and self._is_running:
            job = self.scheduler.get_job("token_cleanup")
            if job and job.next_run_time:
                return cast(datetime, job.next_run_time)
        return None


# Global instance for token cleanup scheduler
token_cleanup_scheduler = TokenCleanupScheduler()
