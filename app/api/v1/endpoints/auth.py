from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.api.dependencies import (
    get_auth_service,
    get_current_admin_user,
    get_current_user,
    oauth2_scheme,
)
from app.core.config import settings
from app.models.user import User
from app.schemas.password_reset import (
    PasswordResetConfirm,
    PasswordResetRequest,
    PasswordResetResponse,
)
from app.schemas.session import (
    SessionInfo,
    SessionInvalidateResponse,
    SessionListResponse,
)
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

    Features:
    - Account lockout after 5 failed attempts
    - Session management with max 5 concurrent sessions
    - Client fingerprinting for enhanced security

    Args:
        request: FastAPI request object (used for rate limiting and fingerprinting)
        form_data: OAuth2 password request form
        auth_service: AuthService instance

    Returns:
        Token object with access and refresh tokens

    Raises:
        HTTPException: If authentication fails,
        account is locked, or rate limit exceeded
    """
    access_token, refresh_token, _ = await auth_service.login(
        email=form_data.username,  # OAuth2 form uses username field for email
        password=form_data.password,
        request=request,
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

    Features:
    - Token rotation detection
    - Client fingerprint validation
    - Automatic security lockdown on reuse detection

    Args:
        request: FastAPI request object (used for rate limiting and fingerprinting)
        refresh_request: Refresh token request
        auth_service: AuthService instance

    Returns:
        Token object with new access and refresh tokens

    Raises:
        HTTPException: If refresh token is invalid, reused, or rate limit exceeded
    """
    access_token, refresh_token = await auth_service.refresh_tokens(
        refresh_token=refresh_request.refresh_token,
        request=request,
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
    logout_all: bool = False,
) -> dict:
    """
    Logout user by invalidating tokens.

    Rate limited to prevent abuse.
    Default: 20 attempts per minute per IP address.

    Args:
        request: FastAPI request object (used for rate limiting)
        token: Access token
        auth_service: AuthService instance
        logout_all: If True, invalidate all user sessions

    Returns:
        Success message

    Raises:
        HTTPException: If token is invalid or rate limit exceeded
    """
    await auth_service.logout(token, invalidate_all_sessions=logout_all)

    message = "All sessions logged out" if logout_all else "Successfully logged out"
    return {"detail": message}


@router.post("/password-reset/request", response_model=PasswordResetResponse)
@limiter.limit(
    settings.RATE_LIMIT_PASSWORD_RESET if not settings.TESTING else "1000/minute"
)
async def request_password_reset(
    request: Request,
    reset_request: PasswordResetRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> PasswordResetResponse:
    """
    Request a password reset code.

    Rate limited to prevent abuse.
    Default: 3 attempts per minute per IP address.

    A 6-digit code will be sent to the email if it exists.
    For security, the response is always the same regardless of email existence.

    Args:
        request: FastAPI request object (used for rate limiting)
        reset_request: Password reset request with email
        auth_service: AuthService instance

    Returns:
        Standard response message
    """
    # Get password reset service
    from app.api.dependencies import get_email_service, get_user_repository
    from app.services.password_reset import PasswordResetService

    user_repo = get_user_repository(auth_service.user_repository.db)
    email_service = await get_email_service()

    password_reset_service = PasswordResetService(
        user_repository=await user_repo,
        email_service=email_service,
    )

    await password_reset_service.request_password_reset(reset_request.email)

    return PasswordResetResponse()


@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
@limiter.limit(
    settings.RATE_LIMIT_PASSWORD_RESET_CONFIRM
    if not settings.TESTING
    else "1000/minute"
)
async def confirm_password_reset(
    request: Request,
    reset_confirm: PasswordResetConfirm,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict:
    """
    Confirm password reset with code.

    Rate limited to prevent brute force attacks.
    Default: 5 attempts per minute per IP address.

    Args:
        request: FastAPI request object (used for rate limiting)
        reset_confirm: Password reset confirmation with code and new password
        auth_service: AuthService instance

    Returns:
        Success message

    Raises:
        HTTPException: If code is invalid, expired, or rate limit exceeded
    """
    # Get password reset service
    from app.api.dependencies import get_email_service, get_user_repository
    from app.services.password_reset import PasswordResetService

    user_repo = get_user_repository(auth_service.user_repository.db)
    email_service = await get_email_service()

    password_reset_service = PasswordResetService(
        user_repository=await user_repo,
        email_service=email_service,
    )

    success = await password_reset_service.confirm_password_reset(
        email=reset_confirm.email,
        code=reset_confirm.code,
        new_password=reset_confirm.new_password,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset code",
        )

    return {"detail": "Password successfully reset"}


@router.get("/sessions", response_model=SessionListResponse)
async def get_user_sessions(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    token: Annotated[str, Depends(oauth2_scheme)],
) -> SessionListResponse:
    """
    Get all sessions for the current user.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        auth_service: AuthService instance
        token: Current access token

    Returns:
        List of user sessions with details
    """
    # Extract values explicitly to avoid SQLAlchemy Column type issues
    user_id = getattr(current_user, "id")

    # Use the renamed method
    sessions, active_count, current_session_id = (
        await auth_service.get_user_sessions_with_current(user_id, token)
    )

    session_infos = []
    for session in sessions:
        session_infos.append(
            SessionInfo(
                id=getattr(session, "id"),
                user_agent=getattr(session, "user_agent", ""),
                ip_address=getattr(session, "ip_address", ""),
                created_at=getattr(session, "created_at"),
                last_activity=getattr(session, "last_activity"),
                expires_at=getattr(session, "expires_at"),
                country=getattr(session, "country", "") or "",
                city=getattr(session, "city", "") or "",
                is_current=(getattr(session, "id") == current_session_id),
            )
        )

    return SessionListResponse(
        sessions=session_infos,
        total=len(sessions),
        active=active_count,
    )


@router.post("/sessions/invalidate-all", response_model=SessionInvalidateResponse)
async def invalidate_all_sessions(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    token: Annotated[str, Depends(oauth2_scheme)],
    except_current: bool = True,
) -> SessionInvalidateResponse:
    """
    Invalidate all sessions for the current user.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        auth_service: AuthService instance
        token: Current access token
        except_current: If True, keep the current session active

    Returns:
        Number of sessions invalidated
    """
    user_id = getattr(current_user, "id")
    count = await auth_service.invalidate_all_user_sessions(
        user_id, except_current_token=token if except_current else None
    )

    return SessionInvalidateResponse(
        message="Sessions invalidated successfully",
        invalidated_count=count,
    )


@router.delete("/sessions/{session_id}", status_code=status.HTTP_200_OK)
async def invalidate_session(
    session_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict:
    """
    Invalidate a specific session.

    Args:
        session_id: ID of session to invalidate
        current_user: Current authenticated user
        auth_service: AuthService instance

    Returns:
        Success message
    """
    user_id = getattr(current_user, "id")
    await auth_service.invalidate_session(user_id, session_id)
    return {"detail": "Session invalidated successfully"}


@router.post("/unlock/{user_id}", status_code=status.HTTP_200_OK)
async def unlock_user_account(
    user_id: int,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict:
    """
    Unlock a user account (admin only).

    Args:
        user_id: ID of user to unlock
        current_admin: Current admin user
        auth_service: AuthService instance

    Returns:
        Success message

    Raises:
        HTTPException: If user not found
    """
    success = await auth_service.account_security.unlock_account(user_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return {"detail": f"User account {user_id} unlocked successfully"}
