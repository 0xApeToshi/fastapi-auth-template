from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.api.dependencies import get_auth_service, oauth2_scheme
from app.core.config import settings
from app.schemas.token import RefreshTokenRequest, Token
from app.services.auth import AuthService

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()


@router.post("/login", response_model=Token)
@limiter.limit(settings.RATE_LIMIT_LOGIN if not settings.TESTING else "1000/minute")
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Token:
    """
    Login user and obtain access and refresh tokens.

    Rate limited to prevent brute force attacks.
    Default: 5 attempts per minute per IP address.

    Args:
        request: FastAPI request object (used for rate limiting)
        form_data: OAuth2 password request form
        auth_service: AuthService instance

    Returns:
        Token object with access and refresh tokens

    Raises:
        HTTPException: If authentication fails or rate limit exceeded
    """
    access_token, refresh_token, _ = await auth_service.login(
        email=form_data.username,  # OAuth2 form uses username field for email
        password=form_data.password,
    )
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=Token)
@limiter.limit(settings.RATE_LIMIT_REFRESH if not settings.TESTING else "1000/minute")
async def refresh_token(
    request: Request,
    refresh_request: RefreshTokenRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Token:
    """
    Refresh access token using refresh token.

    Rate limited to prevent abuse.
    Default: 10 attempts per minute per IP address.

    Args:
        request: FastAPI request object (used for rate limiting)
        refresh_request: Refresh token request
        auth_service: AuthService instance

    Returns:
        Token object with new access and refresh tokens

    Raises:
        HTTPException: If refresh token is invalid or rate limit exceeded
    """
    access_token, refresh_token = await auth_service.refresh_tokens(
        refresh_token=refresh_request.refresh_token,
    )
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
@limiter.limit(settings.RATE_LIMIT_LOGOUT if not settings.TESTING else "1000/minute")
async def logout(
    request: Request,
    token: Annotated[str, Depends(oauth2_scheme)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict:
    """
    Logout user by invalidating tokens.

    Rate limited to prevent abuse.
    Default: 20 attempts per minute per IP address.

    Args:
        request: FastAPI request object (used for rate limiting)
        token: Access token
        auth_service: AuthService instance

    Returns:
        Success message

    Raises:
        HTTPException: If token is invalid or rate limit exceeded
    """
    await auth_service.logout(token)
    return {"detail": "Successfully logged out"}
