from datetime import datetime, timedelta
from typing import Tuple

from fastapi import HTTPException, status
from jose import JWTError, jwt

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, verify_token
from app.models.user import User
from app.repositories.token import TokenRepository
from app.repositories.user import UserRepository
from app.services.user import UserService


class AuthService:
    """Service for authentication operations."""

    def __init__(
        self,
        user_service: UserService,
        user_repository: UserRepository,
        token_repository: TokenRepository,
    ):
        self.user_service = user_service
        self.user_repository = user_repository
        self.token_repository = token_repository

    async def login(self, email: str, password: str) -> Tuple[str, str, User]:
        """
        Authenticate user and generate tokens.

        Args:
            email: User email
            password: Plain text password

        Returns:
            Tuple of (access_token, refresh_token, user)

        Raises:
            HTTPException: If authentication fails
        """
        user = await self.user_service.authenticate(email, password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        # Store refresh token in the database
        refresh_expires = datetime.utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        await self.user_repository.update_refresh_token(
            user_id=int(user.id),
            refresh_token=refresh_token,
            expires_at=refresh_expires,
        )

        return access_token, refresh_token, user

    async def refresh_tokens(self, refresh_token: str) -> Tuple[str, str]:
        """
        Generate new access and refresh tokens using refresh token.

        Args:
            refresh_token: Refresh token

        Returns:
            Tuple of (new_access_token, new_refresh_token)

        Raises:
            HTTPException: If refresh token is invalid or expired
        """
        try:
            # Verify the refresh token
            payload = await verify_token(refresh_token)
            token_type = payload.get("type")

            if token_type != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            user_id = int(payload.get("sub"))

            # Get the user
            user = await self.user_repository.get(user_id)
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid user",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Verify token matches stored token
            if user.refresh_token != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Blacklist the old refresh token (check if not already blacklisted)
            if not await self.token_repository.is_blacklisted(refresh_token):
                token_data = jwt.decode(
                    refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
                )
                expires_at = datetime.fromtimestamp(token_data.get("exp"))
                await self.token_repository.blacklist(refresh_token, expires_at)

            # Generate new tokens
            new_access_token = create_access_token(user_id)
            new_refresh_token = create_refresh_token(user_id)

            # Update stored refresh token
            refresh_expires = datetime.utcnow() + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            )
            await self.user_repository.update_refresh_token(
                user_id=user_id,
                refresh_token=new_refresh_token,
                expires_at=refresh_expires,
            )

            return new_access_token, new_refresh_token

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def logout(self, token: str) -> bool:
        """
        Invalidate user tokens.

        Args:
            token: Access token to invalidate

        Returns:
            True if successful

        Raises:
            HTTPException: If token is invalid
        """
        try:
            # Check if token is already blacklisted
            if await self.token_repository.is_blacklisted(token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token already invalidated",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Verify the token
            payload = await verify_token(token)
            user_id = int(payload.get("sub"))

            # Extract token expiration time
            token_data = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            expires_at = datetime.fromtimestamp(token_data.get("exp"))

            # Blacklist the token
            await self.token_repository.blacklist(token, expires_at)

            # Clear user's refresh token
            await self.user_repository.update_refresh_token(
                user_id=user_id,
                refresh_token=None,
                expires_at=None,
            )

            # Clean expired tokens (maintenance)
            await self.token_repository.clean_expired_tokens()

            return True

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def get_current_user(self, token: str) -> User:
        """
        Get current user from token.

        Args:
            token: JWT access token

        Returns:
            User object

        Raises:
            HTTPException: If token is invalid or user not found
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Check if token is blacklisted
            if await self.token_repository.is_blacklisted(token):
                raise credentials_exception

            # Verify the token
            payload = await verify_token(token)
            token_type = payload.get("type")
            user_id: str = payload.get("sub")

            if user_id is None or token_type != "access":
                raise credentials_exception

        except JWTError:
            raise credentials_exception

        user = await self.user_repository.get(int(user_id))
        if user is None:
            raise credentials_exception

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user
