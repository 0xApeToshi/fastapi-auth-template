from typing import Annotated, List

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from app.api.dependencies import (
    get_current_active_user,
    get_current_admin_user,
    get_user_service,
)
from app.models.user import User
from app.schemas.user import User as UserSchema
from app.schemas.user import UserCreate, UserUpdate
from app.services.user import UserService

router = APIRouter()


@router.post("/", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> User:
    """
    Create new user.

    Args:
        user_in: User creation data
        user_service: UserService instance

    Returns:
        Created user

    Raises:
        HTTPException: If email already registered
    """
    return await user_service.create(user_in)


@router.get("/me", response_model=UserSchema)
async def get_current_user_profile(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """
    Get current user profile.

    Requires authentication using JWT token - either via:
    1. Bearer token in the Authorization header
    2. OAuth2 password flow

    Args:
        current_user: Current authenticated user

    Returns:
        Current user profile
    """
    return current_user


@router.put("/me", response_model=UserSchema)
async def update_current_user_profile(
    user_in: UserUpdate,
    current_user: Annotated[User, Depends(get_current_active_user)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> User:
    """
    Update current user profile.

    Args:
        user_in: User update data
        current_user: Current authenticated user
        user_service: UserService instance

    Returns:
        Updated user profile

    Notes:
        Regular users can't change their own role
    """
    # Regular users can't change their own role
    if user_in.role is not None and user_in.role != current_user.role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change your own role",
        )

    return await user_service.update(current_user.id, user_in)


@router.get("/", response_model=List[UserSchema])
async def list_users(
    user_service: Annotated[UserService, Depends(get_user_service)],
    _: Annotated[User, Depends(get_current_admin_user)],  # Only admins can list users
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(
        100, ge=1, le=100, description="Maximum number of users to return"
    ),
) -> List[User]:
    """
    List all users.

    Args:
        skip: Number of users to skip
        limit: Maximum number of users to return
        _: Current admin user (for authorization)
        user_service: UserService instance

    Returns:
        List of users
    """
    return await user_service.list(skip=skip, limit=limit)


@router.get("/{user_id}", response_model=UserSchema)
async def get_user(
    user_service: Annotated[UserService, Depends(get_user_service)],
    _: Annotated[
        User, Depends(get_current_admin_user)
    ],  # Only admins can get user details
    user_id: int = Path(..., gt=0, description="User ID"),
) -> User:
    """
    Get user by ID.

    Args:
        user_id: User ID
        _: Current admin user (for authorization)
        user_service: UserService instance

    Returns:
        User details

    Raises:
        HTTPException: If user not found
    """
    return await user_service.get(user_id)


@router.put("/{user_id}", response_model=UserSchema)
async def update_user(
    user_in: UserUpdate,
    user_service: Annotated[UserService, Depends(get_user_service)],
    _: Annotated[User, Depends(get_current_admin_user)],  # Only admins can update users
    user_id: int = Path(..., gt=0, description="User ID"),
) -> User:
    """
    Update user.

    Args:
        user_in: User update data
        user_id: User ID
        _: Current admin user (for authorization)
        user_service: UserService instance

    Returns:
        Updated user

    Raises:
        HTTPException: If user not found
    """
    return await user_service.update(user_id, user_in)


@router.delete("/{user_id}", response_model=UserSchema)
async def delete_user(
    user_service: Annotated[UserService, Depends(get_user_service)],
    _: Annotated[User, Depends(get_current_admin_user)],  # Only admins can delete users
    user_id: int = Path(..., gt=0, description="User ID"),
) -> User:
    """
    Delete user.

    Args:
        user_id: User ID
        _: Current admin user (for authorization)
        user_service: UserService instance

    Returns:
        Deleted user

    Raises:
        HTTPException: If user not found
    """
    return await user_service.delete(user_id)
