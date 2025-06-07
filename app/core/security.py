from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

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


def create_access_token(
    subject: Union[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        subject: Token subject (usually user ID)
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expire, "sub": str(subject), "type": "access"}
    encoded_jwt: str = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT refresh token with longer expiration.

    Args:
        subject: Token subject (usually user ID)
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT refresh token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode = {"exp": expire, "sub": str(subject), "type": "refresh"}
    encoded_jwt: str = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash.

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


async def verify_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify a JWT token with enhanced security.

    Args:
        token: JWT token to verify

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
        return payload

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
