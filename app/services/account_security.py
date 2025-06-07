from datetime import datetime, timedelta
from typing import Optional

from app.models.user import User
from app.repositories.user import UserRepository


class AccountSecurityService:
    """
    Service for managing account security features like login attempts and lockouts.
    """

    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30

    async def record_failed_login(self, user: User) -> None:
        """
        Record a failed login attempt and lock account if necessary.

        Args:
            user: User who failed to login
        """
        # Use setattr to avoid mypy Column type issues
        current_attempts = getattr(user, "failed_login_attempts", 0) or 0
        setattr(user, "failed_login_attempts", current_attempts + 1)
        setattr(user, "last_login_attempt", datetime.utcnow())

        # Lock account if max attempts reached
        if current_attempts + 1 >= self.max_failed_attempts:
            lockout_time = datetime.utcnow() + timedelta(
                minutes=self.lockout_duration_minutes
            )
            setattr(user, "locked_until", lockout_time)

        # Update user in database
        await self.user_repository.db.commit()

    async def record_successful_login(self, user: User) -> None:
        """
        Record a successful login and reset failed attempts.

        Args:
            user: User who logged in successfully
        """
        current_time = datetime.utcnow()
        setattr(user, "failed_login_attempts", 0)
        setattr(user, "last_login_attempt", current_time)
        setattr(user, "last_login_at", current_time)
        setattr(user, "locked_until", None)

        await self.user_repository.db.commit()

    async def is_account_locked(self, user: User) -> bool:
        """
        Check if an account is currently locked.

        Args:
            user: User to check

        Returns:
            True if account is locked
        """
        locked_until = getattr(user, "locked_until", None)
        if not locked_until:
            return False

        # Check if lockout has expired
        current_time = datetime.utcnow()
        if current_time >= locked_until:
            # Reset lockout
            setattr(user, "locked_until", None)
            setattr(user, "failed_login_attempts", 0)
            await self.user_repository.db.commit()
            return False

        return True

    async def unlock_account(self, user_id: int) -> bool:
        """
        Manually unlock a user account (admin action).

        Args:
            user_id: ID of user to unlock

        Returns:
            True if account was unlocked
        """
        user = await self.user_repository.get(user_id)
        if not user:
            return False

        setattr(user, "locked_until", None)
        setattr(user, "failed_login_attempts", 0)
        await self.user_repository.db.commit()
        return True

    def get_lockout_remaining_minutes(self, user: User) -> Optional[int]:
        """
        Get remaining lockout time in minutes.

        Args:
            user: Locked user

        Returns:
            Minutes until unlock, or None if not locked
        """
        locked_until = getattr(user, "locked_until", None)
        if not locked_until:
            return None

        remaining = locked_until - datetime.utcnow()
        if remaining.total_seconds() <= 0:
            return None

        return int(remaining.total_seconds() / 60) + 1  # Round up
