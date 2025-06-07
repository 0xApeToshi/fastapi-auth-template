from datetime import datetime, timedelta

import pytest

from app.models.user import UserRole
from app.repositories.user import UserRepository
from app.schemas.user import UserCreate, UserUpdate
from tests.utils.user import create_test_user


@pytest.mark.asyncio
async def test_user_repository_create(test_db):
    """Test UserRepository create method."""
    user_repository = UserRepository(test_db)

    user_create = UserCreate(
        email="test@example.com", password="TestPass1234!", role=UserRole.REGULAR
    )

    user = await user_repository.create(user_create, "hashed_password_123")

    assert user.email == "test@example.com"
    assert user.hashed_password == "hashed_password_123"
    assert user.role == UserRole.REGULAR
    assert user.is_active is True
    assert user.id is not None
    assert user.created_at is not None
    assert user.updated_at is not None


@pytest.mark.asyncio
async def test_user_repository_get(test_db):
    """Test UserRepository get method."""
    user_repository = UserRepository(test_db)

    # Create test user
    created_user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )

    # Get user by ID
    user = await user_repository.get(created_user.id)

    assert user is not None
    assert user.id == created_user.id
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_user_repository_get_not_found(test_db):
    """Test UserRepository get with non-existent user."""
    user_repository = UserRepository(test_db)

    user = await user_repository.get(999)

    assert user is None


@pytest.mark.asyncio
async def test_user_repository_get_by_email(test_db):
    """Test UserRepository get_by_email method."""
    user_repository = UserRepository(test_db)

    # Create test user
    await create_test_user(test_db, email="test@example.com", password="TestPass1234!")

    # Get user by email
    user = await user_repository.get_by_email("test@example.com")

    assert user is not None
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_user_repository_get_by_email_not_found(test_db):
    """Test UserRepository get_by_email with non-existent email."""
    user_repository = UserRepository(test_db)

    user = await user_repository.get_by_email("nonexistent@example.com")

    assert user is None


@pytest.mark.asyncio
async def test_user_repository_list(test_db):
    """Test UserRepository list method."""
    user_repository = UserRepository(test_db)

    # Create test users
    for i in range(5):
        await create_test_user(
            test_db, email=f"user{i}@example.com", password="TestPass1234!"
        )

    # List all users
    users = await user_repository.list()
    assert len(users) == 5

    # List with pagination
    users = await user_repository.list(skip=2, limit=2)
    assert len(users) == 2

    # List with skip only
    users = await user_repository.list(skip=3)
    assert len(users) == 2  # Should get remaining 2 users

    # List with limit only
    users = await user_repository.list(limit=3)
    assert len(users) == 3


@pytest.mark.asyncio
async def test_user_repository_update(test_db):
    """Test UserRepository update method."""
    user_repository = UserRepository(test_db)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )
    original_password = user.hashed_password

    # Update user WITH password in the UserUpdate (this triggers hashed_password usage)
    user_update = UserUpdate(
        email="updated@example.com",
        is_active=False,
        role=UserRole.ADMIN,
        password="NewTestPass1234!",  # This triggers the hashed_password logic
    )

    updated_user = await user_repository.update(
        user.id, user_update, hashed_password="new_hashed_password"
    )

    assert updated_user is not None
    assert updated_user.email == "updated@example.com"
    assert updated_user.is_active is False
    assert updated_user.role == UserRole.ADMIN
    # The hashed_password should be updated when provided
    assert updated_user.hashed_password == "new_hashed_password"
    assert updated_user.hashed_password != original_password

    # Commit the transaction to ensure changes are persisted
    await test_db.commit()


@pytest.mark.asyncio
async def test_user_repository_update_not_found(test_db):
    """Test UserRepository update with non-existent user."""
    user_repository = UserRepository(test_db)

    user_update = UserUpdate(email="updated@example.com")

    updated_user = await user_repository.update(999, user_update)

    assert updated_user is None


@pytest.mark.asyncio
async def test_user_repository_update_partial(test_db):
    """Test UserRepository update with partial data."""
    user_repository = UserRepository(test_db)

    # Create test user
    user = await create_test_user(
        test_db,
        email="test@example.com",
        password="TestPass1234!",
        role=UserRole.REGULAR,
    )

    # Update only email
    user_update = UserUpdate(email="updated@example.com")

    updated_user = await user_repository.update(user.id, user_update)

    assert updated_user is not None
    assert updated_user.email == "updated@example.com"
    assert updated_user.role == UserRole.REGULAR  # Should remain unchanged
    assert updated_user.is_active is True  # Should remain unchanged


@pytest.mark.asyncio
async def test_user_repository_update_password_only(test_db):
    """Test UserRepository update with password only."""
    user_repository = UserRepository(test_db)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )
    original_password = user.hashed_password

    # Update password only
    user_update = UserUpdate(password="NewTestPass1234!")

    updated_user = await user_repository.update(
        user.id, user_update, hashed_password="new_hashed_password"
    )

    assert updated_user is not None
    assert updated_user.email == "test@example.com"  # Should remain unchanged
    assert updated_user.hashed_password == "new_hashed_password"
    assert updated_user.hashed_password != original_password

    # Commit the changes
    await test_db.commit()


@pytest.mark.asyncio
async def test_user_repository_delete(test_db):
    """Test UserRepository delete method."""
    user_repository = UserRepository(test_db)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )

    # Delete user
    deleted_user = await user_repository.delete(user.id)

    assert deleted_user is not None
    assert deleted_user.id == user.id
    assert deleted_user.email == "test@example.com"

    # Commit the deletion
    await test_db.commit()

    # Verify user is deleted
    get_user = await user_repository.get(user.id)
    assert get_user is None


@pytest.mark.asyncio
async def test_user_repository_delete_not_found(test_db):
    """Test UserRepository delete with non-existent user."""
    user_repository = UserRepository(test_db)

    deleted_user = await user_repository.delete(999)

    assert deleted_user is None


@pytest.mark.asyncio
async def test_user_repository_update_refresh_token(test_db):
    """Test UserRepository update_refresh_token method with hashing."""
    user_repository = UserRepository(test_db)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )

    # Update refresh token - note: this will be hashed now
    refresh_token = "test_refresh_token_123"
    expires_at = datetime.utcnow() + timedelta(days=7)

    success = await user_repository.update_refresh_token(
        user.id, refresh_token, expires_at
    )

    assert success is True

    # Verify token was updated and hashed
    updated_user = await user_repository.get(user.id)
    assert updated_user.refresh_token is not None
    # The stored token should be hashed, not the original
    assert updated_user.refresh_token != refresh_token
    # But we should be able to verify it
    assert await user_repository.verify_refresh_token(user.id, refresh_token) is True
    assert updated_user.refresh_token_expires_at == expires_at


@pytest.mark.asyncio
async def test_user_repository_verify_refresh_token(test_db):
    """Test UserRepository verify_refresh_token method."""
    user_repository = UserRepository(test_db)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )

    # Set refresh token
    refresh_token = "test_refresh_token_456"
    await user_repository.update_refresh_token(
        user.id, refresh_token, datetime.utcnow() + timedelta(days=7)
    )

    # Verify correct token
    assert await user_repository.verify_refresh_token(user.id, refresh_token) is True

    # Verify wrong token
    assert await user_repository.verify_refresh_token(user.id, "wrong_token") is False

    # Verify for non-existent user
    assert await user_repository.verify_refresh_token(999, refresh_token) is False


@pytest.mark.asyncio
async def test_user_repository_update_refresh_token_clear(test_db):
    """Test UserRepository update_refresh_token with None (clear token)."""
    user_repository = UserRepository(test_db)

    # Create test user with refresh token
    user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )

    # Set initial refresh token
    await user_repository.update_refresh_token(
        user.id, "initial_token", datetime.utcnow() + timedelta(days=7)
    )

    # Clear refresh token
    success = await user_repository.update_refresh_token(user.id, None, None)

    assert success is True

    # Verify token was cleared
    updated_user = await user_repository.get(user.id)
    assert updated_user.refresh_token is None
    assert updated_user.refresh_token_expires_at is None


@pytest.mark.asyncio
async def test_user_repository_update_refresh_token_not_found(test_db):
    """Test UserRepository update_refresh_token with non-existent user."""
    user_repository = UserRepository(test_db)

    success = await user_repository.update_refresh_token(
        999, "test_token", datetime.utcnow() + timedelta(days=7)
    )

    assert success is False


@pytest.mark.asyncio
async def test_user_repository_create_with_defaults(test_db):
    """Test UserRepository create with default values."""
    user_repository = UserRepository(test_db)

    # Create user with minimal data (using defaults)
    user_create = UserCreate(
        email="minimal@example.com",
        password="TestPass1234!",
        # No role specified - should default to REGULAR
        # No is_active specified - should default to True
    )

    user = await user_repository.create(user_create, "hashed_password")

    assert user.email == "minimal@example.com"
    assert user.role == UserRole.REGULAR  # Default value
    assert user.is_active is True  # Default value


@pytest.mark.asyncio
async def test_user_repository_create_admin(test_db):
    """Test UserRepository create with admin role."""
    user_repository = UserRepository(test_db)

    user_create = UserCreate(
        email="admin@example.com",
        password="AdminPass123!",
        role=UserRole.ADMIN,
        is_active=True,
    )

    user = await user_repository.create(user_create, "hashed_admin_password")

    assert user.email == "admin@example.com"
    assert user.role == UserRole.ADMIN
    assert user.is_active is True


@pytest.mark.asyncio
async def test_user_repository_create_inactive(test_db):
    """Test UserRepository create with inactive user."""
    user_repository = UserRepository(test_db)

    user_create = UserCreate(
        email="inactive@example.com", password="InactivePass123!", is_active=False
    )

    user = await user_repository.create(user_create, "hashed_password")

    assert user.email == "inactive@example.com"
    assert user.is_active is False
    assert user.role == UserRole.REGULAR  # Default role


@pytest.mark.asyncio
async def test_user_repository_list_empty(test_db):
    """Test UserRepository list with no users."""
    user_repository = UserRepository(test_db)

    users = await user_repository.list()

    assert len(users) == 0


@pytest.mark.asyncio
async def test_user_repository_list_pagination_edge_cases(test_db):
    """Test UserRepository list pagination edge cases."""
    user_repository = UserRepository(test_db)

    # Create 3 test users
    for i in range(3):
        await create_test_user(
            test_db, email=f"user{i}@example.com", password="TestPass1234!"
        )

    # Test skip beyond available records
    users = await user_repository.list(skip=10, limit=5)
    assert len(users) == 0

    # Test limit larger than available records
    users = await user_repository.list(skip=0, limit=100)
    assert len(users) == 3

    # Test skip at boundary
    users = await user_repository.list(skip=3, limit=5)
    assert len(users) == 0

    # Test limit = 0 (should return no results)
    users = await user_repository.list(skip=0, limit=0)
    assert len(users) == 0


@pytest.mark.asyncio
async def test_user_repository_update_no_changes(test_db):
    """Test UserRepository update with no actual changes."""
    user_repository = UserRepository(test_db)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="TestPass1234!"
    )

    # Update with empty data
    user_update = UserUpdate()

    updated_user = await user_repository.update(user.id, user_update)

    assert updated_user is not None
    assert updated_user.email == "test@example.com"
    assert updated_user.role == user.role
    assert updated_user.is_active == user.is_active
