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
    
    # Add a small delay to ensure tokens are generated at different times
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
    # New tokens should be different
    assert data["access_token"] != tokens["access_token"]
    assert data["refresh_token"] != tokens["refresh_token"]


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
    
    # Try to use token after logout (should fail)
    me_response = await client.get(
        f"{settings.API_V1_STR}/users/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    
    assert me_response.status_code == status.HTTP_401_UNAUTHORIZED