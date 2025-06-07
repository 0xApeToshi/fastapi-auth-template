import secrets
from datetime import datetime, timedelta

from app.core.security import get_password_hash, verify_password
from app.repositories.user import UserRepository
from app.services.email import EmailService


class PasswordResetService:
    """Service for handling password reset functionality."""

    def __init__(
        self,
        user_repository: UserRepository,
        email_service: EmailService,
    ):
        self.user_repository = user_repository
        self.email_service = email_service
        self.reset_code_expiry_minutes = 30
        self.max_reset_attempts = 3

    async def request_password_reset(self, email: str) -> bool:
        """
        Request a password reset for the given email.

        Args:
            email: User's email address

        Returns:
            True (always, to prevent email enumeration)
        """
        user = await self.user_repository.get_by_email(email)

        if user and user.is_active:
            # Generate 6-digit PIN code
            reset_code = self._generate_reset_code()

            # Hash the code before storing
            hashed_code = get_password_hash(reset_code)

            # Set expiration time
            expires_at = datetime.utcnow() + timedelta(
                minutes=self.reset_code_expiry_minutes
            )

            # Update user with reset code - convert SQLAlchemy Column to int
            user_id = int(user.id)
            await self.user_repository.update_password_reset_code(
                user_id=user_id,
                reset_code_hash=hashed_code,
                expires_at=expires_at,
                reset_attempts=0,
            )

            # Send email with code
            await self.email_service.send_password_reset_email(
                to_email=email,
                reset_code=reset_code,
                expires_in_minutes=self.reset_code_expiry_minutes,
            )

        # Always return True to prevent email enumeration
        return True

    async def confirm_password_reset(
        self, email: str, code: str, new_password: str
    ) -> bool:
        """
        Confirm password reset with code and set new password.

        Args:
            email: User's email address
            code: 6-digit reset code
            new_password: New password to set

        Returns:
            True if password was reset successfully
        """
        user = await self.user_repository.get_by_email(email)

        if not user:
            return False

        # Extract user ID as integer
        user_id = int(user.id)

        # Check if user has a valid reset code
        if not user.password_reset_code or not user.password_reset_expires_at:
            return False

        # Check if code has expired
        if datetime.utcnow() > user.password_reset_expires_at:
            # Clear expired code
            await self.user_repository.clear_password_reset_code(user_id)
            return False

        # Check if too many attempts
        current_attempts = (
            int(user.password_reset_attempts) if user.password_reset_attempts else 0
        )
        if current_attempts >= self.max_reset_attempts:
            # Clear code due to too many attempts
            await self.user_repository.clear_password_reset_code(user_id)
            return False

        # Verify the code - convert SQLAlchemy Column to string
        stored_code_hash = str(user.password_reset_code)
        if not verify_password(code, stored_code_hash):
            # Increment attempt counter
            await self.user_repository.increment_password_reset_attempts(user_id)
            return False

        # Code is valid - update password
        hashed_password = get_password_hash(new_password)
        await self.user_repository.update_password(user_id, hashed_password)

        # Clear reset code
        await self.user_repository.clear_password_reset_code(user_id)

        # Invalidate all user sessions for security
        from app.models.user import TokenBlacklistReason
        from app.repositories.token import TokenRepository

        token_repo = TokenRepository(self.user_repository.db)
        await token_repo.invalidate_all_user_tokens(
            user_id, TokenBlacklistReason.PASSWORD_RESET
        )

        return True

    async def is_reset_code_valid(self, email: str) -> bool:
        """
        Check if user has a valid (non-expired) reset code.

        Args:
            email: User's email address

        Returns:
            True if user has a valid reset code
        """
        user = await self.user_repository.get_by_email(email)

        if not user or not user.password_reset_expires_at:
            return False

        # Convert SQLAlchemy ColumnElement to actual boolean value
        current_time = datetime.utcnow()
        expires_at = user.password_reset_expires_at

        # Explicit comparison to get a proper boolean
        is_valid = current_time < expires_at
        return bool(is_valid)

    def _generate_reset_code(self) -> str:
        """Generate a 6-digit reset code."""
        return "".join([str(secrets.randbelow(10)) for _ in range(6)])
