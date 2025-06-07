import pytest
from fastapi import HTTPException

from app.models.user import UserRole
from app.repositories.user import UserRepository
from app.schemas.user import UserCreate, UserUpdate
from app.services.user import UserService
from tests.utils.user import create_test_user


@pytest.mark.asyncio
async def test_user_service_create(test_db):
    """Test UserService create method."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    user_create = UserCreate(
        email="test@example.com", password="password123", role=UserRole.REGULAR
    )

    user = await user_service.create(user_create)

    assert user.email == "test@example.com"
    assert user.role == UserRole.REGULAR
    assert user.is_active is True
    assert user.id is not None


@pytest.mark.asyncio
async def test_user_service_create_duplicate_email(test_db):
    """Test UserService create with duplicate email."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create first user
    await create_test_user(test_db, email="test@example.com", password="password123")

    # Try to create second user with same email
    user_create = UserCreate(
        email="test@example.com", password="password123", role=UserRole.REGULAR
    )

    with pytest.raises(HTTPException) as exc_info:
        await user_service.create(user_create)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Email already registered"


@pytest.mark.asyncio
async def test_user_service_get(test_db):
    """Test UserService get method."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    created_user = await create_test_user(
        test_db, email="test@example.com", password="password123"
    )

    # Get user
    user = await user_service.get(created_user.id)

    assert user.id == created_user.id
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_user_service_get_not_found(test_db):
    """Test UserService get with non-existent user."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    with pytest.raises(HTTPException) as exc_info:
        await user_service.get(999)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "User not found"


@pytest.mark.asyncio
async def test_user_service_get_by_email(test_db):
    """Test UserService get_by_email method."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    await create_test_user(test_db, email="test@example.com", password="password123")

    # Get user by email
    user = await user_service.get_by_email("test@example.com")

    assert user is not None
    assert user.email == "test@example.com"

    # Try non-existent email
    user = await user_service.get_by_email("nonexistent@example.com")
    assert user is None


@pytest.mark.asyncio
async def test_user_service_authenticate_success(test_db):
    """Test UserService authenticate with correct credentials."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    await create_test_user(test_db, email="test@example.com", password="password123")

    # Authenticate
    user = await user_service.authenticate("test@example.com", "password123")

    assert user is not None
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_user_service_authenticate_wrong_password(test_db):
    """Test UserService authenticate with wrong password."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    await create_test_user(test_db, email="test@example.com", password="password123")

    # Try wrong password
    user = await user_service.authenticate("test@example.com", "wrongpassword")

    assert user is None


@pytest.mark.asyncio
async def test_user_service_authenticate_nonexistent_user(test_db):
    """Test UserService authenticate with non-existent user."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Try non-existent user
    user = await user_service.authenticate("nonexistent@example.com", "password123")

    assert user is None


@pytest.mark.asyncio
async def test_user_service_list(test_db):
    """Test UserService list method."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test users
    for i in range(5):
        await create_test_user(
            test_db, email=f"user{i}@example.com", password="password123"
        )

    # List all users
    users = await user_service.list()
    assert len(users) == 5

    # List with pagination
    users = await user_service.list(skip=2, limit=2)
    assert len(users) == 2


@pytest.mark.asyncio
async def test_user_service_update(test_db):
    """Test UserService update method."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="password123"
    )

    # Update user
    user_update = UserUpdate(
        email="updated@example.com", password="newpassword123", is_active=False
    )

    updated_user = await user_service.update(user.id, user_update)

    assert updated_user.email == "updated@example.com"
    assert updated_user.is_active is False

    # Verify password was updated (authenticate with new password)
    auth_user = await user_service.authenticate("updated@example.com", "newpassword123")
    assert auth_user is not None


@pytest.mark.asyncio
async def test_user_service_update_not_found(test_db):
    """Test UserService update with non-existent user."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    user_update = UserUpdate(email="updated@example.com")

    with pytest.raises(HTTPException) as exc_info:
        await user_service.update(999, user_update)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "User not found"


@pytest.mark.asyncio
async def test_user_service_update_duplicate_email(test_db):
    """Test UserService update with duplicate email."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create two users
    user1 = await create_test_user(
        test_db, email="user1@example.com", password="password123"
    )
    await create_test_user(test_db, email="user2@example.com", password="password123")

    # Try to update user1 with user2's email
    user_update = UserUpdate(email="user2@example.com")

    with pytest.raises(HTTPException) as exc_info:
        await user_service.update(user1.id, user_update)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Email already registered"


@pytest.mark.asyncio
async def test_user_service_update_same_email(test_db):
    """Test UserService update with same email (should work)."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="password123"
    )

    # Update user with same email but different role
    user_update = UserUpdate(
        email="test@example.com", role=UserRole.ADMIN  # Same email
    )

    updated_user = await user_service.update(user.id, user_update)

    assert updated_user.email == "test@example.com"
    assert updated_user.role == UserRole.ADMIN


@pytest.mark.asyncio
async def test_user_service_update_partial(test_db):
    """Test UserService update with partial data."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="password123", role=UserRole.REGULAR
    )

    # Update only the role
    user_update = UserUpdate(role=UserRole.ADMIN)

    updated_user = await user_service.update(user.id, user_update)

    # Email should remain the same
    assert updated_user.email == "test@example.com"
    # Role should be updated
    assert updated_user.role == UserRole.ADMIN
    # Should still be active
    assert updated_user.is_active is True


@pytest.mark.asyncio
async def test_user_service_update_password_only(test_db):
    """Test UserService update with password only."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="password123"
    )

    # Update only the password
    user_update = UserUpdate(password="newpassword456")

    updated_user = await user_service.update(user.id, user_update)

    # Email should remain the same
    assert updated_user.email == "test@example.com"

    # Old password should not work
    auth_old = await user_service.authenticate("test@example.com", "password123")
    assert auth_old is None

    # New password should work
    auth_new = await user_service.authenticate("test@example.com", "newpassword456")
    assert auth_new is not None


@pytest.mark.asyncio
async def test_user_service_delete(test_db):
    """Test UserService delete method."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create test user
    user = await create_test_user(
        test_db, email="test@example.com", password="password123"
    )

    # Delete user
    deleted_user = await user_service.delete(user.id)

    assert deleted_user.id == user.id
    assert deleted_user.email == "test@example.com"

    # Commit the transaction
    await test_db.commit()

    # User should no longer exist
    with pytest.raises(HTTPException) as exc_info:
        await user_service.get(user.id)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "User not found"


@pytest.mark.asyncio
async def test_user_service_delete_not_found(test_db):
    """Test UserService delete with non-existent user."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    with pytest.raises(HTTPException) as exc_info:
        await user_service.delete(999)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "User not found"


@pytest.mark.asyncio
async def test_user_service_create_admin_user(test_db):
    """Test UserService create with admin role."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    user_create = UserCreate(
        email="admin@example.com", password="password123", role=UserRole.ADMIN
    )

    user = await user_service.create(user_create)

    assert user.email == "admin@example.com"
    assert user.role == UserRole.ADMIN
    assert user.is_active is True


@pytest.mark.asyncio
async def test_user_service_create_inactive_user(test_db):
    """Test UserService create with inactive user."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    user_create = UserCreate(
        email="inactive@example.com", password="password123", is_active=False
    )

    user = await user_service.create(user_create)

    assert user.email == "inactive@example.com"
    assert user.is_active is False
    assert user.role == UserRole.REGULAR  # Default role


@pytest.mark.asyncio
async def test_user_service_authenticate_inactive_user(test_db):
    """Test UserService authenticate with inactive user."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create inactive user
    await create_test_user(
        test_db, email="inactive@example.com", password="password123", is_active=False
    )

    # Try to authenticate - should work even if inactive
    # (The auth service layer handles active/inactive logic)
    user = await user_service.authenticate("inactive@example.com", "password123")

    assert user is not None
    assert user.email == "inactive@example.com"
    assert user.is_active is False


@pytest.mark.asyncio
async def test_user_service_list_empty(test_db):
    """Test UserService list with no users."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    users = await user_service.list()
    assert len(users) == 0


@pytest.mark.asyncio
async def test_user_service_list_pagination_edge_cases(test_db):
    """Test UserService list pagination edge cases."""
    user_repository = UserRepository(test_db)
    user_service = UserService(user_repository)

    # Create 3 test users
    for i in range(3):
        await create_test_user(
            test_db, email=f"user{i}@example.com", password="password123"
        )

    # Test skip beyond available records
    users = await user_service.list(skip=10, limit=5)
    assert len(users) == 0

    # Test limit larger than available records
    users = await user_service.list(skip=0, limit=100)
    assert len(users) == 3

    # Test skip + limit combination
    users = await user_service.list(skip=1, limit=1)
    assert len(users) == 1
