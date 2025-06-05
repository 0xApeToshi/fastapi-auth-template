from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.dependencies import get_auth_service, oauth2_scheme
from app.schemas.token import RefreshTokenRequest, Token
from app.services.auth import AuthService

router = APIRouter()


@router.post("/login", response_model=Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Token:
    """
    Login user and obtain access and refresh tokens.
    
    Args:
        form_data: OAuth2 password request form
        auth_service: AuthService instance
        
    Returns:
        Token object with access and refresh tokens
        
    Raises:
        HTTPException: If authentication fails
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
async def refresh_token(
    refresh_request: RefreshTokenRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Token:
    """
    Refresh access token using refresh token.
    
    Args:
        refresh_request: Refresh token request
        auth_service: AuthService instance
        
    Returns:
        Token object with new access and refresh tokens
        
    Raises:
        HTTPException: If refresh token is invalid
    """
    access_token, refresh_token = await auth_service.refresh_tokens(
        refresh_token=refresh_request.refresh_token,
    )
    return Token(
        access_token=access_token, 
        refresh_token=refresh_token,
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    token: Annotated[str, Depends(oauth2_scheme)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict:
    """
    Logout user by invalidating tokens.
    
    Args:
        token: Access token
        auth_service: AuthService instance
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If token is invalid
    """
    await auth_service.logout(token)
    return {"detail": "Successfully logged out"}