import os
import sys
from typing import AsyncGenerator
from unittest.mock import MagicMock

# Add the parent directory to the Python path to make 'app' importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.db.base import Base
from app.main import app
from app.repositories.token import token_cleanup_scheduler

# Use in-memory SQLite for testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Create async engine for testing
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
    future=True,
)

# Create async session factory
TestAsyncSessionLocal = sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_test_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency override for database session."""
    async with TestAsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@pytest_asyncio.fixture
async def test_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a fresh database on each test case.

    We use a separate fixture from `get_test_db` so that
    we can perform database setup before yielding the session.
    """
    # Create all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Use the session
    async with TestAsyncSessionLocal() as session:
        yield session

    # Drop all tables after the test
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def override_get_db():
    """Override the get_db dependency."""
    return get_test_db


@pytest.fixture
def test_app(override_get_db) -> FastAPI:
    """Create a test app with overridden dependencies and disabled rate limiting."""
    # Store original components for cleanup
    original_limiter = getattr(app.state, "limiter", None)
    original_exception_handlers = app.exception_handlers.copy()

    # Override database dependency
    app.dependency_overrides[get_db] = override_get_db

    # Create a mock limiter that disables all rate limiting
    mock_limiter = MagicMock()

    # Make the limiter appear disabled
    mock_limiter.enabled = False

    # Mock the _check_request_limit method to be a no-op
    mock_limiter._check_request_limit = MagicMock()

    # Mock the _inject_headers method to return response unchanged
    mock_limiter._inject_headers = MagicMock(
        side_effect=lambda response, limit: response
    )

    # Create no-op decorators
    def no_op_decorator(*args, **kwargs):
        def decorator(func):
            return func  # Return function unchanged

        return decorator

    mock_limiter.limit = no_op_decorator
    mock_limiter.shared_limit = no_op_decorator
    mock_limiter.exempt = lambda func: func

    # Set the mock limiter on the app state
    app.state.limiter = mock_limiter

    # Create a custom rate limit exception handler that doesn't access request.state
    def mock_rate_limit_handler(request, exc):
        from starlette.responses import JSONResponse

        return JSONResponse(
            {"error": f"Rate limit exceeded: {exc.detail}"}, status_code=429
        )

    # Override the rate limit exception handler
    from slowapi.errors import RateLimitExceeded

    app.exception_handlers[RateLimitExceeded] = mock_rate_limit_handler

    # Ensure token cleanup scheduler is stopped during tests
    if token_cleanup_scheduler.is_running:
        token_cleanup_scheduler.stop_scheduler()

    # Store cleanup function
    def cleanup():
        # Restore original state
        if original_limiter:
            app.state.limiter = original_limiter
        else:
            delattr(app.state, "limiter")
        app.exception_handlers.clear()
        app.exception_handlers.update(original_exception_handlers)
        # Clear dependency overrides
        app.dependency_overrides.clear()

    app._test_cleanup = cleanup

    return app


@pytest_asyncio.fixture
async def client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client for the app."""
    # Use ASGITransport for newer versions of httpx
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    # Cleanup after tests
    if hasattr(test_app, "_test_cleanup"):
        test_app._test_cleanup()
