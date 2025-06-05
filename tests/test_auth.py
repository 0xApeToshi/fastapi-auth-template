import pytest
import asyncio
from fastapi import status
from httpx import AsyncClient

from app.core.config import settings
from app.models.user import UserRole
from tests.utils.user import create_test_user


@pytest.mark.asyncio
async def test_login(client: AsyncClient, test_db):
    """Test login endpoint."""
    # Create a test user
    user_data = {
        "email": "test@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    # Try to login
    login_data = {
        "username": user_data["email"],  # OAuth2 form uses username field
        "password": user_data["password"],
    }
    response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, test_db):
    """Test login with wrong password."""
    # Create a test user
    user_data = {
        "email": "test2@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    # Try to login with wrong password
    login_data = {
        "username": user_data["email"],
        "password": "wrong_password",
    }
    response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient, test_db):
    """Test login with non-existent user."""
    login_data = {
        "username": "nonexistent@example.com",
        "password": "password123",
    }
    response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert data["detail"] == "Incorrect email or password"


@pytest.mark.asyncio
async def test_login_inactive_user(client: AsyncClient, test_db):
    """Test login with inactive user."""
    # Create an inactive test user
    user_data = {
        "email": "inactive@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
        "is_active": False,
    }
    await create_test_user(test_db, **user_data)
    
    # Try to login
    login_data = {
        "username": user_data["email"],
        "password": user_data["password"],
    }
    response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert data["detail"] == "Inactive user"


@pytest.mark.asyncio
async def test_login_missing_credentials(client: AsyncClient, test_db):
    """Test login with missing credentials."""
    # Missing password
    response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data={"username": "test@example.com"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    # Missing username
    response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data={"password": "password123"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_refresh_token(client: AsyncClient, test_db):
    """Test refresh token endpoint."""
    # Create a test user
    user_data = {
        "email": "test3@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    # Login to get tokens
    login_data = {
        "username": user_data["email"],
        "password": user_data["password"],
    }
    login_response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    tokens = login_response.json()
    
    # Add a longer delay to ensure tokens are generated at different times
    # JWT tokens include expiration time in seconds, so we need at least 1 second difference
    await asyncio.sleep(1.1)
    
    # Try to refresh tokens
    refresh_data = {
        "refresh_token": tokens["refresh_token"],
    }
    response = await client.post(
        f"{settings.API_V1_STR}/auth/refresh", 
        json=refresh_data,
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    # New tokens should be different (since they were generated at different times)
    assert data["access_token"] != tokens["access_token"]
    assert data["refresh_token"] != tokens["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_token_invalid(client: AsyncClient, test_db):
    """Test refresh token with invalid token."""
    refresh_data = {
        "refresh_token": "invalid_token",
    }
    response = await client.post(
        f"{settings.API_V1_STR}/auth/refresh", 
        json=refresh_data,
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert data["detail"] == "Invalid refresh token"


@pytest.mark.asyncio
async def test_refresh_token_with_access_token(client: AsyncClient, test_db):
    """Test refresh token endpoint with access token instead of refresh token."""
    # Create a test user and login
    user_data = {
        "email": "test_refresh_access@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    login_data = {
        "username": user_data["email"],
        "password": user_data["password"],
    }
    login_response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    tokens = login_response.json()
    
    # Try to refresh using access token instead of refresh token
    refresh_data = {
        "refresh_token": tokens["access_token"],  # Wrong token type
    }
    response = await client.post(
        f"{settings.API_V1_STR}/auth/refresh", 
        json=refresh_data,
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert data["detail"] == "Invalid token type"


@pytest.mark.asyncio
async def test_refresh_token_reuse_after_refresh(client: AsyncClient, test_db):
    """Test that old refresh token can't be reused after refresh."""
    # Create a test user and login
    user_data = {
        "email": "test_reuse@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    login_data = {
        "username": user_data["email"],
        "password": user_data["password"],
    }
    login_response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    original_tokens = login_response.json()
    
    await asyncio.sleep(1.1)
    
    # First refresh - should work
    refresh_data = {
        "refresh_token": original_tokens["refresh_token"],
    }
    first_refresh_response = await client.post(
        f"{settings.API_V1_STR}/auth/refresh", 
        json=refresh_data,
    )
    assert first_refresh_response.status_code == status.HTTP_200_OK
    
    # Try to use the same refresh token again - should fail
    second_refresh_response = await client.post(
        f"{settings.API_V1_STR}/auth/refresh", 
        json=refresh_data,
    )
    assert second_refresh_response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_logout(client: AsyncClient, test_db):
    """Test logout endpoint."""
    # Create a test user
    user_data = {
        "email": "test4@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    # Login to get tokens
    login_data = {
        "username": user_data["email"],
        "password": user_data["password"],
    }
    login_response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    tokens = login_response.json()
    
    # Logout
    response = await client.post(
        f"{settings.API_V1_STR}/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["detail"] == "Successfully logged out"
    
    # Try to use token after logout (should fail)
    me_response = await client.get(
        f"{settings.API_V1_STR}/users/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    
    assert me_response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_logout_invalid_token(client: AsyncClient, test_db):
    """Test logout with invalid token."""
    response = await client.post(
        f"{settings.API_V1_STR}/auth/logout",
        headers={"Authorization": "Bearer invalid_token"},
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_logout_missing_token(client: AsyncClient, test_db):
    """Test logout without token."""
    response = await client.post(f"{settings.API_V1_STR}/auth/logout")
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_logout_twice(client: AsyncClient, test_db):
    """Test logout twice with same token."""
    # Create a test user and login
    user_data = {
        "email": "test_logout_twice@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    login_data = {
        "username": user_data["email"],
        "password": user_data["password"],
    }
    login_response = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    tokens = login_response.json()
    
    # First logout - should work
    first_logout = await client.post(
        f"{settings.API_V1_STR}/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert first_logout.status_code == status.HTTP_200_OK
    
    # Second logout with same token - should fail with "Token already invalidated"
    second_logout = await client.post(
        f"{settings.API_V1_STR}/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert second_logout.status_code == status.HTTP_401_UNAUTHORIZED
    data = second_logout.json()
    assert data["detail"] == "Token already invalidated"


@pytest.mark.asyncio
async def test_multiple_logins_different_tokens(client: AsyncClient, test_db):
    """Test that multiple logins generate different tokens."""
    # Create a test user
    user_data = {
        "email": "test_multiple@example.com",
        "password": "password123",
        "role": UserRole.REGULAR,
    }
    await create_test_user(test_db, **user_data)
    
    login_data = {
        "username": user_data["email"],
        "password": user_data["password"],
    }
    
    # First login
    response1 = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    tokens1 = response1.json()
    
    await asyncio.sleep(1.1)  # Ensure different timestamps
    
    # Second login
    response2 = await client.post(
        f"{settings.API_V1_STR}/auth/login", 
        data=login_data,
    )
    tokens2 = response2.json()
    
    # Tokens should be different
    assert tokens1["access_token"] != tokens2["access_token"]
    assert tokens1["refresh_token"] != tokens2["refresh_token"]
    
    # Both tokens should work
    me_response1 = await client.get(
        f"{settings.API_V1_STR}/users/me",
        headers={"Authorization": f"Bearer {tokens1['access_token']}"},
    )
    assert me_response1.status_code == status.HTTP_200_OK
    
    me_response2 = await client.get(
        f"{settings.API_V1_STR}/users/me",
        headers={"Authorization": f"Bearer {tokens2['access_token']}"},
    )
    assert me_response2.status_code == status.HTTP_200_OK