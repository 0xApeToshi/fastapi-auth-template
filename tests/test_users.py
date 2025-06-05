import pytest
from fastapi import status
from httpx import AsyncClient

from app.core.config import settings
from app.models.user import UserRole
from tests.utils.user import create_test_user, get_user_auth_headers


@pytest.mark.asyncio
async def test_create_user(client: AsyncClient, test_db):
    """Test user creation endpoint."""
    user_data = {
        "email": "newuser@example.com",
        "password": "password123",
        "is_active": True,
        "role": "regular",
    }

    response = await client.post(
        f"{settings.API_V1_STR}/users/",
        json=user_data,
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["is_active"] == user_data["is_active"]
    assert data["role"] == user_data["role"]
    assert "id" in data
    assert "created_at" in data
    assert "updated_at" in data
    # Password should not be returned
    assert "password" not in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_create_user_duplicate_email(client: AsyncClient, test_db):
    """Test creating user with duplicate email."""
    # Create first user
    user_data = {
        "email": "duplicate@example.com",
        "password": "password123",
    }
    await create_test_user(test_db, **user_data)

    # Try to create second user with same email
    response = await client.post(
        f"{settings.API_V1_STR}/users/",
        json=user_data,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert data["detail"] == "Email already registered"


@pytest.mark.asyncio
async def test_create_user_invalid_email(client: AsyncClient, test_db):
    """Test creating user with invalid email."""
    user_data = {
        "email": "invalid-email",
        "password": "password123",
    }

    response = await client.post(
        f"{settings.API_V1_STR}/users/",
        json=user_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_create_user_short_password(client: AsyncClient, test_db):
    """Test creating user with short password."""
    user_data = {
        "email": "shortpass@example.com",
        "password": "123",  # Too short
    }

    response = await client.post(
        f"{settings.API_V1_STR}/users/",
        json=user_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_create_user_admin_role(client: AsyncClient, test_db):
    """Test creating user with admin role."""
    user_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": "admin",
    }

    response = await client.post(
        f"{settings.API_V1_STR}/users/",
        json=user_data,
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["role"] == "admin"


@pytest.mark.asyncio
async def test_get_current_user_profile(client: AsyncClient, test_db):
    """Test getting current user profile."""
    # Create a test user
    user_data = {
        "email": "profile@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)

    # Get auth headers
    headers = await get_user_auth_headers(
        client, user_data["email"], user_data["password"], settings.API_V1_STR
    )

    # Get current user profile
    response = await client.get(
        f"{settings.API_V1_STR}/users/me",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["role"] == user_data["role"].value
    assert "id" in data


@pytest.mark.asyncio
async def test_get_current_user_profile_unauthenticated(client: AsyncClient, test_db):
    """Test getting current user profile without authentication."""
    response = await client.get(f"{settings.API_V1_STR}/users/me")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_update_current_user_profile(client: AsyncClient, test_db):
    """Test updating current user profile."""
    # Create a test user
    user_data = {
        "email": "update@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    user = await create_test_user(test_db, **user_data)  # noqa

    # Get auth headers
    headers = await get_user_auth_headers(
        client, user_data["email"], user_data["password"], settings.API_V1_STR
    )

    # Update user profile
    update_data = {"email": "updated@example.com", "password": "newpassword123"}
    response = await client.put(
        f"{settings.API_V1_STR}/users/me",
        json=update_data,
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["email"] == update_data["email"]

    # Verify old credentials don't work
    old_headers_response = await client.post(
        f"{settings.API_V1_STR}/auth/login",
        data={"username": user_data["email"], "password": user_data["password"]},
    )
    assert old_headers_response.status_code == status.HTTP_401_UNAUTHORIZED

    # Verify new credentials work
    new_headers_response = await client.post(
        f"{settings.API_V1_STR}/auth/login",
        data={"username": update_data["email"], "password": update_data["password"]},
    )
    assert new_headers_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_update_current_user_role_forbidden(client: AsyncClient, test_db):
    """Test that regular users can't change their own role."""
    # Create a test user
    user_data = {
        "email": "role_change@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)

    # Get auth headers
    headers = await get_user_auth_headers(
        client, user_data["email"], user_data["password"], settings.API_V1_STR
    )

    # Try to update role
    update_data = {"role": "admin"}
    response = await client.put(
        f"{settings.API_V1_STR}/users/me",
        json=update_data,
        headers=headers,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    data = response.json()
    assert data["detail"] == "Cannot change your own role"


@pytest.mark.asyncio
async def test_list_users_admin(client: AsyncClient, test_db):
    """Test listing users as admin."""
    # Create admin user
    admin_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": UserRole.ADMIN,
    }
    await create_test_user(test_db, **admin_data)

    # Create regular users
    for i in range(3):
        await create_test_user(
            test_db,
            email=f"user{i}@example.com",
            password="password123",
            role=UserRole.REGULAR,
        )

    # Get admin auth headers
    headers = await get_user_auth_headers(
        client, admin_data["email"], admin_data["password"], settings.API_V1_STR
    )

    # List users
    response = await client.get(
        f"{settings.API_V1_STR}/users/",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 4  # 1 admin + 3 regular users

    # Check pagination
    response = await client.get(
        f"{settings.API_V1_STR}/users/?skip=1&limit=2",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 2


@pytest.mark.asyncio
async def test_list_users_regular_user_forbidden(client: AsyncClient, test_db):
    """Test that regular users can't list users."""
    # Create regular user
    user_data = {
        "email": "regular@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)

    # Get auth headers
    headers = await get_user_auth_headers(
        client, user_data["email"], user_data["password"], settings.API_V1_STR
    )

    # Try to list users
    response = await client.get(
        f"{settings.API_V1_STR}/users/",
        headers=headers,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_get_user_by_id_admin(client: AsyncClient, test_db):
    """Test getting user by ID as admin."""
    # Create admin user
    admin_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": UserRole.ADMIN,
    }
    await create_test_user(test_db, **admin_data)

    # Create target user
    target_user = await create_test_user(
        test_db,
        email="target@example.com",
        password="password123",
        role=UserRole.REGULAR,
    )

    # Get admin auth headers
    headers = await get_user_auth_headers(
        client, admin_data["email"], admin_data["password"], settings.API_V1_STR
    )

    # Get user by ID
    response = await client.get(
        f"{settings.API_V1_STR}/users/{target_user.id}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["email"] == "target@example.com"
    assert data["id"] == target_user.id


@pytest.mark.asyncio
async def test_get_user_by_id_not_found(client: AsyncClient, test_db):
    """Test getting non-existent user by ID."""
    # Create admin user
    admin_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": UserRole.ADMIN,
    }
    await create_test_user(test_db, **admin_data)

    # Get admin auth headers
    headers = await get_user_auth_headers(
        client, admin_data["email"], admin_data["password"], settings.API_V1_STR
    )

    # Try to get non-existent user
    response = await client.get(
        f"{settings.API_V1_STR}/users/999",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_update_user_admin(client: AsyncClient, test_db):
    """Test updating user as admin."""
    # Create admin user
    admin_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": UserRole.ADMIN,
    }
    await create_test_user(test_db, **admin_data)

    # Create target user
    target_user = await create_test_user(
        test_db,
        email="target@example.com",
        password="password123",
        role=UserRole.REGULAR,
    )

    # Get admin auth headers
    headers = await get_user_auth_headers(
        client, admin_data["email"], admin_data["password"], settings.API_V1_STR
    )

    # Update user
    update_data = {
        "email": "updated_target@example.com",
        "role": "admin",
        "is_active": False,
    }
    response = await client.put(
        f"{settings.API_V1_STR}/users/{target_user.id}",
        json=update_data,
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["email"] == update_data["email"]
    assert data["role"] == update_data["role"]
    assert data["is_active"] == update_data["is_active"]


@pytest.mark.asyncio
async def test_delete_user_admin(client: AsyncClient, test_db):
    """Test deleting user as admin."""
    # Create admin user
    admin_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": UserRole.ADMIN,
    }
    await create_test_user(test_db, **admin_data)

    # Create target user
    target_user = await create_test_user(
        test_db,
        email="target@example.com",
        password="password123",
        role=UserRole.REGULAR,
    )

    # Get admin auth headers
    headers = await get_user_auth_headers(
        client, admin_data["email"], admin_data["password"], settings.API_V1_STR
    )

    # Delete user
    response = await client.delete(
        f"{settings.API_V1_STR}/users/{target_user.id}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["email"] == "target@example.com"

    # Verify user is deleted
    get_response = await client.get(
        f"{settings.API_V1_STR}/users/{target_user.id}",
        headers=headers,
    )
    assert get_response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_delete_user_not_found(client: AsyncClient, test_db):
    """Test deleting non-existent user."""
    # Create admin user
    admin_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": UserRole.ADMIN,
    }
    await create_test_user(test_db, **admin_data)

    # Get admin auth headers
    headers = await get_user_auth_headers(
        client, admin_data["email"], admin_data["password"], settings.API_V1_STR
    )

    # Try to delete non-existent user
    response = await client.delete(
        f"{settings.API_V1_STR}/users/999",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_admin_operations_regular_user_forbidden(client: AsyncClient, test_db):
    """Test that regular users can't perform admin operations."""
    # Create regular user
    user_data = {
        "email": "regular@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    user = await create_test_user(test_db, **user_data)  # noqa

    # Create another user to target
    target_user = await create_test_user(
        test_db,
        email="target@example.com",
        password="password123",
        role=UserRole.REGULAR,
    )

    # Get regular user auth headers
    headers = await get_user_auth_headers(
        client, user_data["email"], user_data["password"], settings.API_V1_STR
    )

    # Try admin operations
    operations = [
        ("GET", f"{settings.API_V1_STR}/users/{target_user.id}"),
        (
            "PUT",
            f"{settings.API_V1_STR}/users/{target_user.id}",
            {"email": "new@example.com"},
        ),
        ("DELETE", f"{settings.API_V1_STR}/users/{target_user.id}"),
    ]

    for method, url, *json_data in operations:
        if method == "GET":
            response = await client.get(url, headers=headers)
        elif method == "PUT":
            response = await client.put(url, headers=headers, json=json_data[0])
        elif method == "DELETE":
            response = await client.delete(url, headers=headers)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = response.json()
        assert data["detail"] == "Not enough permissions"


@pytest.mark.asyncio
async def test_pagination_parameters(client: AsyncClient, test_db):
    """Test pagination parameters validation."""
    # Create admin user
    admin_data = {
        "email": "admin@example.com",
        "password": "password123",
        "role": UserRole.ADMIN,
    }
    await create_test_user(test_db, **admin_data)

    # Get admin auth headers
    headers = await get_user_auth_headers(
        client, admin_data["email"], admin_data["password"], settings.API_V1_STR
    )

    # Test invalid skip parameter
    response = await client.get(
        f"{settings.API_V1_STR}/users/?skip=-1",
        headers=headers,
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Test invalid limit parameter
    response = await client.get(
        f"{settings.API_V1_STR}/users/?limit=0",
        headers=headers,
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Test limit too high
    response = await client.get(
        f"{settings.API_V1_STR}/users/?limit=101",
        headers=headers,
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
