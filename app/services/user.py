from typing import List, Optional

from fastapi import HTTPException, status

from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.user import UserCreate, UserUpdate


class UserService:
    """Service for user-related operations."""

    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    async def get(self, user_id: int) -> User:
        """
        Get user by ID.

        Args:
            user_id: User ID

        Returns:
            User object

        Raises:
            HTTPException: If user not found
        """
        user = await self.user_repository.get(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user

    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.

        Args:
            email: User email

        Returns:
            User object or None
        """
        return await self.user_repository.get_by_email(email)

    async def authenticate(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate a user with constant-time operations to prevent timing attacks.

        Args:
            email: User email
            password: Plain text password

        Returns:
            User object if authentication successful, None otherwise
        """
        user = await self.get_by_email(email)

        # Always perform password verification to prevent timing attacks
        if user:
            password_valid = verify_password(password, str(user.hashed_password))
            if password_valid and user.is_active:
                return user
        else:
            # Perform dummy hash operation to maintain constant timing
            # This prevents timing attacks that could reveal user existence
            get_password_hash("dummy_password_to_maintain_timing")

        return None

    async def list(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        List users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of User objects
        """
        return await self.user_repository.list(skip=skip, limit=limit)

    async def create(self, user_in: UserCreate) -> User:
        """
        Create a new user.

        Args:
            user_in: User creation data

        Returns:
            Created User object

        Raises:
            HTTPException: If email already registered
        """
        user = await self.user_repository.get_by_email(user_in.email)
        if user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        hashed_password = get_password_hash(user_in.password)
        return await self.user_repository.create(user_in, hashed_password)

    async def update(self, user_id: int, user_in: UserUpdate) -> User:
        """
        Update a user.

        Args:
            user_id: User ID
            user_in: User update data

        Returns:
            Updated User object

        Raises:
            HTTPException: If user not found or email already taken
        """
        user = await self.user_repository.get(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # If email is being updated, check it's not already taken
        if user_in.email is not None and user_in.email != user.email:
            existing_user = await self.user_repository.get_by_email(user_in.email)
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered",
                )

        # Hash password if provided
        hashed_password = None
        if user_in.password:
            hashed_password = get_password_hash(user_in.password)

        updated_user = await self.user_repository.update(
            user_id=user_id,
            user_update=user_in,
            hashed_password=hashed_password,
        )

        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return updated_user

    async def delete(self, user_id: int) -> User:
        """
        Delete a user.

        Args:
            user_id: User ID

        Returns:
            Deleted User object

        Raises:
            HTTPException: If user not found
        """
        user = await self.user_repository.delete(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user
