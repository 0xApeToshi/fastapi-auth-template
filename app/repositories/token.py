from datetime import datetime
from typing import Optional, cast

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.user import BlacklistedToken


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

    async def blacklist(self, token: str, expires_at: datetime) -> BlacklistedToken:
        """
        Add a token to blacklist.

        Args:
            token: JWT token to blacklist
            expires_at: Token expiration date

        Returns:
            BlacklistedToken object
        """
        blacklisted_token = BlacklistedToken(token=token, expires_at=expires_at)
        self.db.add(blacklisted_token)
        await self.db.flush()
        return blacklisted_token

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
