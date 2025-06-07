from datetime import datetime
from typing import List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate


class UserRepository:
    """Repository for user model operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, user_id: int) -> Optional[User]:
        """
        Get a user by ID.

        Args:
            user_id: The user ID

        Returns:
            User object if found, None otherwise
        """
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalars().first()

    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by email.

        Args:
            email: User email

        Returns:
            User object if found, None otherwise
        """
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalars().first()

    async def list(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get a list of users with pagination.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of User objects
        """
        result = await self.db.execute(select(User).offset(skip).limit(limit))
        return list(result.scalars().all())

    async def create(self, user_create: UserCreate, hashed_password: str) -> User:
        """
        Create a new user.

        Args:
            user_create: User creation data
            hashed_password: Hashed user password

        Returns:
            Created User object
        """
        db_user = User(
            email=user_create.email,
            hashed_password=hashed_password,
            is_active=user_create.is_active,
            role=user_create.role or UserRole.REGULAR,
        )
        self.db.add(db_user)
        await self.db.flush()
        await self.db.refresh(db_user)
        return db_user

    async def update(
        self,
        user_id: int,
        user_update: UserUpdate,
        hashed_password: Optional[str] = None,
    ) -> Optional[User]:
        """
        Update a user.

        Args:
            user_id: User ID
            user_update: User update data
            hashed_password: Optional new hashed password

        Returns:
            Updated User object or None if not found
        """
        # Get the user
        user = await self.get(user_id)
        if not user:
            return None

        # Build update values
        update_data = user_update.dict(exclude_unset=True)

        # Replace password with hashed version if provided
        if "password" in update_data:
            del update_data["password"]
            if hashed_password:
                update_data["hashed_password"] = hashed_password

        # Update user
        if update_data:
            stmt = (
                update(User)
                .where(User.id == user_id)
                .values(**update_data)
                .execution_options(synchronize_session="fetch")
            )
            await self.db.execute(stmt)
            await self.db.refresh(user)

        return user

    async def delete(self, user_id: int) -> Optional[User]:
        """
        Delete a user.

        Args:
            user_id: User ID

        Returns:
            Deleted User object or None if not found
        """
        user = await self.get(user_id)
        if not user:
            return None

        await self.db.delete(user)
        return user

    async def update_refresh_token(
        self,
        user_id: int,
        refresh_token: Optional[str],
        expires_at: Optional[datetime] = None,
    ) -> bool:
        """
        Update a user's refresh token.

        Args:
            user_id: User ID
            refresh_token: New refresh token or None to clear
            expires_at: Token expiration date

        Returns:
            True if successful, False otherwise
        """
        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(refresh_token=refresh_token, refresh_token_expires_at=expires_at)
            .execution_options(synchronize_session="fetch")
        )
        result = await self.db.execute(stmt)
        return result.rowcount > 0
