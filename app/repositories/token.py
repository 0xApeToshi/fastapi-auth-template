from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

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
        return result.rowcount
