from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union
from uuid import uuid4

from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# Configure Argon2 with recommended parameters
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__time_cost=settings.ARGON2_TIME_COST,
    argon2__memory_cost=settings.ARGON2_MEMORY_COST,
    argon2__parallelism=settings.ARGON2_PARALLELISM,
    argon2__hash_len=settings.ARGON2_HASH_LENGTH,
    argon2__salt_len=settings.ARGON2_SALT_LENGTH,
)

# Pre-computed dummy hash for constant-time operations
DUMMY_HASH = (
    "$argon2id$v=19$m=102400,t=2,p=8$tNGFwKmxMGYNOkiBcVaIcQ$HXxLgJLqSBKFwHnLHTdBNA"
)


def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    fingerprint: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    Create a JWT access token with enhanced security features.

    Args:
        subject: Token subject (usually user ID)
        expires_delta: Optional expiration time delta
        fingerprint: Optional client fingerprint for binding
        session_id: Optional session identifier

    Returns:
        Encoded JWT token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access",
        "jti": str(uuid4()),  # Unique token ID
        "iat": datetime.utcnow(),  # Issued at
    }

    # Add optional claims
    if fingerprint:
        to_encode["fingerprint"] = fingerprint
    if session_id:
        to_encode["sid"] = session_id

    encoded_jwt: str = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    fingerprint: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    Create a JWT refresh token with longer expiration and security features.

    Args:
        subject: Token subject (usually user ID)
        expires_delta: Optional expiration time delta
        fingerprint: Optional client fingerprint for binding
        session_id: Optional session identifier

    Returns:
        Encoded JWT refresh token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "refresh",
        "jti": str(uuid4()),  # Unique token ID
        "iat": datetime.utcnow(),  # Issued at
    }

    # Add optional claims
    if fingerprint:
        to_encode["fingerprint"] = fingerprint
    if session_id:
        to_encode["sid"] = session_id

    encoded_jwt: str = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash using constant-time comparison.

    Args:
        plain_password: Password in plain text
        hashed_password: Hashed password

    Returns:
        True if password matches hash
    """
    result: bool = pwd_context.verify(plain_password, hashed_password)
    return result


def get_password_hash(password: str) -> str:
    """
    Hash a password using Argon2.

    Args:
        password: Password in plain text

    Returns:
        Hashed password
    """
    hashed: str = pwd_context.hash(password)
    return hashed


def hash_refresh_token(refresh_token: str) -> str:
    """
    Hash a refresh token for secure storage.

    Args:
        refresh_token: Refresh token to hash

    Returns:
        Hashed refresh token
    """
    return get_password_hash(refresh_token)


def verify_refresh_token(provided_token: str, stored_hash: str) -> bool:
    """
    Verify a refresh token against its stored hash.

    Args:
        provided_token: Refresh token provided by client
        stored_hash: Stored hash of the refresh token

    Returns:
        True if tokens match
    """
    return verify_password(provided_token, stored_hash)


async def verify_token(
    token: str, expected_fingerprint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Decode and verify a JWT token with enhanced security.

    Args:
        token: JWT token to verify
        expected_fingerprint: Expected fingerprint to validate against

    Returns:
        Token payload if valid

    Raises:
        HTTPException: If token is invalid
    """
    try:
        # Parse header first to verify algorithm
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg") != settings.ALGORITHM:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token algorithm",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify with strict algorithm enforcement and required claims
        payload: Dict[str, Any] = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={
                "verify_signature": True,
                "require": ["exp", "sub", "type"],
                "verify_exp": True,
                "verify_sub": True,
            },
        )

        # Verify fingerprint if provided
        if expected_fingerprint and "fingerprint" in payload:
            if payload["fingerprint"] != expected_fingerprint:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token fingerprint",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return payload

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def perform_constant_time_password_verification(password: str) -> None:
    """
    Perform a dummy password verification for timing attack prevention.
    This should be called when a user doesn't exist to maintain constant timing.

    Args:
        password: The password to "verify" against dummy hash
    """
    verify_password(password, DUMMY_HASH)
