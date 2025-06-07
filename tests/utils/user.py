from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.user import User, UserRole


async def create_test_user(
    db: AsyncSession,
    *,
    email: str,
    password: str = "TestPass1234!",
    role: UserRole = UserRole.REGULAR,
    is_active: bool = True,
) -> User:
    """
    Create a user in the database for testing.

    Args:
        db: Database session
        email: User email
        password: Plain text password (default meets new requirements)
        role: User role
        is_active: Whether the user is active

    Returns:
        Created User object
    """
    hashed_password = get_password_hash(password)
    db_user = User(
        email=email,
        hashed_password=hashed_password,
        role=role,
        is_active=is_active,
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    return db_user


async def get_user_auth_headers(
    client,
    email: str,
    password: str,
    api_prefix: str,
) -> dict:
    """
    Get authentication headers for a user.

    Args:
        client: Test client
        email: User email
        password: User password
        api_prefix: API prefix (e.g. "/api/v1")

    Returns:
        Dict with Authorization header
    """
    login_data = {
        "username": email,  # OAuth2 form uses username field
        "password": password,
    }
    response = await client.post(
        f"{api_prefix}/auth/login",
        data=login_data,
    )

    if response.status_code != 200:
        raise Exception(f"Login failed: {response.status_code} - {response.text}")

    tokens = response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}
