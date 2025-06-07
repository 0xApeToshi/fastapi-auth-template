from datetime import datetime, timedelta
from typing import List, Optional, Tuple
from uuid import uuid4

from fastapi import HTTPException, Request, status
from jose import JWTError, jwt

from app.core.config import settings
from app.core.fingerprint import generate_fingerprint, verify_fingerprint
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_refresh_token,
    verify_token,
)
from app.models.session import UserSession
from app.models.user import TokenBlacklistReason, User
from app.repositories.session import SessionRepository
from app.repositories.token import TokenRepository
from app.repositories.user import UserRepository
from app.services.account_security import AccountSecurityService
from app.services.user import UserService


class AuthService:
    """Service for authentication operations with enhanced security."""

    def __init__(
        self,
        user_service: UserService,
        user_repository: UserRepository,
        token_repository: TokenRepository,
    ):
        self.user_service = user_service
        self.user_repository = user_repository
        self.token_repository = token_repository
        self.account_security = AccountSecurityService(user_repository)

    async def login(
        self, email: str, password: str, request: Request
    ) -> Tuple[str, str, User]:
        """
        Authenticate user and generate tokens with session management.

        Fixed to properly handle session tokens without double hashing.
        """
        user = await self.user_service.get_by_email(email)

        # Check if account is locked before attempting authentication
        if user and await self.account_security.is_account_locked(user):
            remaining_minutes = self.account_security.get_lockout_remaining_minutes(
                user
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account locked. Try again in {remaining_minutes} minutes.",
            )

        # Authenticate user (constant-time operation)
        authenticated_user = await self.user_service.authenticate(email, password)

        if not authenticated_user:
            # Record failed attempt if user exists
            if user:
                await self.account_security.record_failed_login(user)
                if await self.account_security.is_account_locked(user):
                    remaining_minutes = (
                        self.account_security.get_lockout_remaining_minutes(user)
                    )
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Too many failed attempts. Account locked for {remaining_minutes} minutes.",  # noqa
                    )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not authenticated_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Record successful login
        await self.account_security.record_successful_login(authenticated_user)

        # Check concurrent sessions
        session_repo = SessionRepository(self.user_repository.db)
        user_id = int(authenticated_user.id)
        active_sessions = await session_repo.count_active_sessions(user_id)

        if active_sessions >= settings.MAX_CONCURRENT_SESSIONS:
            # Remove oldest session
            oldest_session = await session_repo.get_oldest_active_session(user_id)
            if oldest_session:
                session_id = int(oldest_session.id)
                await session_repo.delete_session(session_id)

        # Generate client fingerprint
        fingerprint = generate_fingerprint(request)
        from app.core.fingerprint import get_client_ip

        # FIXED: Generate session token that will be stored in JWT
        # This token should NOT be hashed here - let the repository handle hashing
        session_token = str(uuid4())

        # Create JWT tokens with the raw session token
        access_token = create_access_token(
            user_id,
            fingerprint=fingerprint,
            session_id=session_token,  # Raw UUID, not hashed
        )
        refresh_token = create_refresh_token(
            user_id,
            fingerprint=fingerprint,
            session_id=session_token,  # Raw UUID, not hashed
        )

        # Store session - repository will handle hashing
        expires_at = datetime.utcnow() + timedelta(days=settings.SESSION_EXPIRE_DAYS)
        await session_repo.create(
            user_id=user_id,
            session_token=session_token,  # Raw token - will be hashed in repository
            refresh_token=refresh_token,  # Raw token - will be hashed in repository
            user_agent=request.headers.get("User-Agent"),
            ip_address=get_client_ip(request),
            fingerprint=fingerprint,
            expires_at=expires_at,
        )

        # Store refresh token hash in the user table (for backward compatibility)
        refresh_expires = datetime.utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        await self.user_repository.update_refresh_token(
            user_id=user_id,
            refresh_token=refresh_token,
            expires_at=refresh_expires,
        )

        return access_token, refresh_token, authenticated_user

    async def get_current_user(self, token: str, request: Request) -> User:
        """
        Get current user from token with fingerprint validation.
        Fixed session activity update logic.
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Check if token is blacklisted
            if await self.token_repository.is_blacklisted(token):
                raise credentials_exception

            # Verify the token with fingerprint
            fingerprint = generate_fingerprint(request)
            payload = await verify_token(token, fingerprint)

            token_type = payload.get("type")
            user_id: str = payload.get("sub")

            if user_id is None or token_type != "access":
                raise credentials_exception

        except JWTError:
            raise credentials_exception

        user_id_int = int(user_id)
        user = await self.user_repository.get(user_id_int)
        if user is None:
            raise credentials_exception

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # FIXED: Update session activity properly
        session_id = payload.get("sid")  # This is the raw UUID from JWT
        if session_id:
            session_repo = SessionRepository(self.user_repository.db)
            # Find session by comparing raw token with hashed stored token
            sessions = await session_repo.get_user_sessions(user_id_int)
            session_token_hash = hash_refresh_token(
                session_id
            )  # Hash the raw token for comparison

            for session in sessions:
                if str(session.session_token) == session_token_hash:
                    session_db_id = int(session.id)
                    await session_repo.update_activity(session_db_id)
                    break

        return user

    async def get_user_sessions_with_current(
        self, user_id: int, current_token: str
    ) -> Tuple[List[UserSession], int, Optional[int]]:
        """
        Get all sessions for a user with current session identification.
        Fixed session identification logic.
        """
        session_repo = SessionRepository(self.user_repository.db)
        sessions = await session_repo.get_user_sessions(user_id)

        # Identify current session properly
        current_session_id = None
        try:
            # Decode the JWT to get the session ID
            payload = jwt.decode(
                current_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )

            session_token = payload.get("sid")  # This is the raw UUID

            if session_token:
                # Hash the raw token to compare with stored hashed tokens
                session_token_hash = hash_refresh_token(session_token)

                for session in sessions:
                    stored_token = str(session.session_token)

                    if stored_token == session_token_hash:
                        current_session_id = int(session.id)
                        break

        except Exception as e:
            print(f"Error identifying current session: {e}")

        # Count active sessions
        active_count = sum(1 for session in sessions if session.is_active())

        return sessions, active_count, current_session_id

    async def logout(self, token: str, invalidate_all_sessions: bool = False) -> bool:
        """
        Invalidate user tokens and optionally all sessions.
        Fixed session deletion logic.
        """
        try:
            # Check if token is already blacklisted
            if await self.token_repository.is_blacklisted(token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token already invalidated",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Verify the token
            payload = await verify_token(token)
            user_id = int(payload.get("sub"))
            session_id = payload.get("sid")  # Raw UUID

            # Extract token expiration time
            token_data = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            expires_at = datetime.fromtimestamp(token_data.get("exp"))

            # Blacklist the token
            await self.token_repository.blacklist(
                token, expires_at, user_id, TokenBlacklistReason.LOGOUT
            )

            if invalidate_all_sessions:
                # Invalidate all user tokens and sessions
                await self.token_repository.invalidate_all_user_tokens(
                    user_id, TokenBlacklistReason.LOGOUT
                )
            else:
                # Clear user's refresh token
                await self.user_repository.update_refresh_token(
                    user_id=user_id,
                    refresh_token=None,
                    expires_at=None,
                )

                # FIXED: Delete the specific session if session_id exists
                if session_id:
                    session_repo = SessionRepository(self.user_repository.db)
                    sessions = await session_repo.get_user_sessions(user_id)
                    session_token_hash = hash_refresh_token(
                        session_id
                    )  # Hash for comparison

                    for session in sessions:
                        if str(session.session_token) == session_token_hash:
                            session_db_id = int(session.id)
                            await session_repo.delete_session(session_db_id)
                            break

            return True

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def refresh_tokens(
        self, refresh_token: str, request: Request
    ) -> Tuple[str, str]:
        """
        Generate new access and refresh tokens with rotation detection.
        Fixed session update logic.
        """
        try:
            # Check for token reuse attack
            payload = await verify_token(refresh_token)
            user_id = int(payload.get("sub"))

            # Check if token has been reused
            if await self.token_repository.check_token_reuse(refresh_token, user_id):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token reuse detected - all sessions terminated for security",  # noqa
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Verify the refresh token
            token_type = payload.get("type")
            if token_type != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Get the user
            user = await self.user_repository.get(user_id)
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid user",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Verify fingerprint if present
            if "fingerprint" in payload:
                if not verify_fingerprint(request, payload.get("fingerprint")):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid client fingerprint",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

            # Verify token matches stored token hash
            if not await self.user_repository.verify_refresh_token(
                user_id, refresh_token
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Blacklist the old refresh token
            token_data = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            expires_at = datetime.fromtimestamp(token_data.get("exp"))
            await self.token_repository.blacklist(
                refresh_token, expires_at, user_id, TokenBlacklistReason.REFRESH
            )

            # Generate new tokens with same session
            session_id = payload.get("sid")  # Raw UUID
            fingerprint = generate_fingerprint(request)

            new_access_token = create_access_token(
                user_id,
                fingerprint=fingerprint,
                session_id=session_id,
            )
            new_refresh_token = create_refresh_token(
                user_id,
                fingerprint=fingerprint,
                session_id=session_id,
            )

            # Update stored refresh token hash
            refresh_expires = datetime.utcnow() + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            )
            await self.user_repository.update_refresh_token(
                user_id=user_id,
                refresh_token=new_refresh_token,
                expires_at=refresh_expires,
            )

            # FIXED: Update session activity properly
            if session_id:
                session_repo = SessionRepository(self.user_repository.db)
                sessions = await session_repo.get_user_sessions(
                    user_id, only_active=True
                )
                session_token_hash = hash_refresh_token(
                    session_id
                )  # Hash for comparison

                for session in sessions:
                    if str(session.session_token) == session_token_hash:
                        session_db_id = int(session.id)
                        await session_repo.update_activity(session_db_id)
                        break

            return new_access_token, new_refresh_token

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def invalidate_all_user_sessions(
        self, user_id: int, except_current_token: Optional[str] = None
    ) -> int:
        """
        Invalidate all sessions for a user, optionally keeping current.
        Fixed current session identification.
        """
        session_repo = SessionRepository(self.user_repository.db)

        except_session_id = None
        if except_current_token:
            # FIXED: Identify current session to preserve
            try:
                payload = await verify_token(except_current_token)
                session_token = payload.get("sid")  # Raw UUID
                if session_token:
                    sessions = await session_repo.get_user_sessions(user_id)
                    session_token_hash = hash_refresh_token(
                        session_token
                    )  # Hash for comparison
                    for session in sessions:
                        if str(session.session_token) == session_token_hash:
                            except_session_id = int(session.id)
                            break
            except (JWTError, HTTPException):
                # Failed to verify token, invalidate all sessions
                pass

        # Delete sessions
        if except_session_id:
            return await session_repo.delete_user_sessions(
                user_id, except_session_id=except_session_id
            )
        else:
            return await self.token_repository.invalidate_all_user_tokens(
                user_id, TokenBlacklistReason.SECURITY
            )

    async def invalidate_session(self, user_id: int, session_id: int) -> None:
        """
        Invalidate a specific session.
        """
        session_repo = SessionRepository(self.user_repository.db)

        # Verify session belongs to user
        sessions = await session_repo.get_user_sessions(user_id)
        session_found = any(int(session.id) == session_id for session in sessions)

        if not session_found:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found",
            )

        # Delete the session
        deleted = await session_repo.delete_session(session_id)

        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete session",
            )
