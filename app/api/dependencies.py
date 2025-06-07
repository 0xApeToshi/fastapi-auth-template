from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordBearer,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import User, UserRole
from app.repositories.session import SessionRepository
from app.repositories.token import TokenRepository
from app.repositories.user import UserRepository
from app.services.auth import AuthService
from app.services.email import EmailService, MockEmailService
from app.services.user import UserService

# OAuth2 password bearer scheme for login endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# HTTP bearer scheme for explicit JWT tokens
http_bearer = HTTPBearer()

# Common type annotations
DbSession = Annotated[AsyncSession, Depends(get_db)]


async def get_user_repository(db: DbSession) -> UserRepository:
    """
    Dependency for UserRepository.

    Args:
        db: Database session

    Returns:
        UserRepository instance
    """
    return UserRepository(db)


async def get_token_repository(db: DbSession) -> TokenRepository:
    """
    Dependency for TokenRepository.

    Args:
        db: Database session

    Returns:
        TokenRepository instance
    """
    return TokenRepository(db)


async def get_session_repository(db: DbSession) -> SessionRepository:
    """
    Dependency for SessionRepository.

    Args:
        db: Database session

    Returns:
        SessionRepository instance
    """
    return SessionRepository(db)


async def get_user_service(
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
) -> UserService:
    """
    Dependency for UserService.

    Args:
        user_repository: UserRepository instance

    Returns:
        UserService instance
    """
    return UserService(user_repository)


async def get_auth_service(
    user_service: Annotated[UserService, Depends(get_user_service)],
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
    token_repository: Annotated[TokenRepository, Depends(get_token_repository)],
) -> AuthService:
    """
    Dependency for AuthService.

    Args:
        user_service: UserService instance
        user_repository: UserRepository instance
        token_repository: TokenRepository instance

    Returns:
        AuthService instance
    """
    return AuthService(user_service, user_repository, token_repository)


async def get_email_service() -> EmailService:
    """
    Dependency for EmailService.

    Returns:
        EmailService instance (MockEmailService for now)
    """
    # In production, you would return a real email service implementation
    # based on your configuration (SendGrid, AWS SES, etc.)
    return MockEmailService()


async def get_token_from_bearer(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
) -> str:
    """
    Extract token from HTTP Bearer authentication.

    Args:
        credentials: HTTP Authorization credentials

    Returns:
        JWT token
    """
    return credentials.credentials


# Support both OAuth2 password flow and explicit HTTP Bearer tokens
async def get_token(
    oauth2_token: Optional[str] = Depends(oauth2_scheme),
    bearer_token: Optional[str] = None,
) -> str:
    """
    Get token from either OAuth2 or HTTP Bearer authentication.

    Args:
        oauth2_token: Token from OAuth2 authentication
        bearer_token: Token from HTTP Bearer authentication

    Returns:
        JWT token

    Raises:
        HTTPException: If no token is provided
    """
    if bearer_token:
        return bearer_token
    if oauth2_token:
        return oauth2_token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    request: Request,
    token: Annotated[str, Depends(get_token)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> User:
    """
    Dependency for current authenticated user with fingerprint validation.

    Args:
        request: FastAPI request for fingerprint validation
        token: JWT token from request
        auth_service: AuthService instance

    Returns:
        Current user
    """
    return await auth_service.get_current_user(token, request)


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """
    Dependency for current active user.

    Args:
        current_user: Current authenticated user

    Returns:
        Current active user

    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return current_user


async def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """
    Dependency for current admin user.

    Args:
        current_user: Current active user

    Returns:
        Current admin user

    Raises:
        HTTPException: If user is not an admin
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user
