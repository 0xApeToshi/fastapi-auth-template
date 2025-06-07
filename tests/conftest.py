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
from app.core.config import Settings, generate_secret_key
from app.db.base import Base
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
def test_settings():
    """Create test-specific settings that override production settings."""
    return Settings(
        # Security - use test-safe values
        SECRET_KEY=generate_secret_key(),
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
        REFRESH_TOKEN_EXPIRE_DAYS=7,
        ALGORITHM="HS256",
        # Database - test database (though we use SQLite in memory)
        POSTGRES_USER="test_user",
        POSTGRES_PASSWORD="test_password",
        POSTGRES_DB="test_db",
        POSTGRES_HOST="localhost",
        POSTGRES_PORT="5432",
        # Security settings - disable for testing
        HTTPS_REDIRECT=False,
        SECURE_COOKIES=False,
        # Session management
        MAX_CONCURRENT_SESSIONS=5,
        SESSION_EXPIRE_DAYS=30,
        # Account security
        MAX_FAILED_LOGIN_ATTEMPTS=5,
        ACCOUNT_LOCKOUT_MINUTES=15,
        # Password reset
        PASSWORD_RESET_CODE_EXPIRE_MINUTES=15,
        # Password settings
        ARGON2_TIME_COST=1,  # Reduced for faster tests
        ARGON2_MEMORY_COST=65536,  # Reduced for faster tests
        ARGON2_PARALLELISM=4,  # Reduced for faster tests
        ARGON2_HASH_LENGTH=16,
        ARGON2_SALT_LENGTH=16,
        # Rate limiting - will be disabled by mock anyway
        RATE_LIMIT_LOGIN="1000/minute",
        RATE_LIMIT_REFRESH="1000/minute",
        RATE_LIMIT_LOGOUT="1000/minute",
        RATE_LIMIT_REGISTER="1000/minute",
        RATE_LIMIT_LIST_USERS="1000/minute",
        RATE_LIMIT_PASSWORD_RESET="1000/minute",
        # Testing flag
        TESTING=True,
        # CORS
        BACKEND_CORS_ORIGINS="",
        # API
        API_V1_STR="/api/v1",
        PROJECT_NAME="Test User Management API",
    )


@pytest.fixture
def override_get_db():
    """Override the get_db dependency."""
    return get_test_db


@pytest.fixture
def test_app(override_get_db, test_settings) -> FastAPI:
    """Create a test app with overridden dependencies and disabled rate limiting."""
    # Import here to avoid circular imports and ensure fresh app instance
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    # Override settings globally for the test
    import app.core.config as config_module
    from app.api.v1.router import api_router

    original_settings = config_module.settings
    config_module.settings = test_settings

    # Create a fresh app instance for testing
    app = FastAPI(
        title=test_settings.PROJECT_NAME,
        description="Test User management API with JWT authentication and enhanced security",  # noqa
        version="2.0.0",
        openapi_url=f"{test_settings.API_V1_STR}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Create a mock limiter that disables all rate limiting
    mock_limiter = MagicMock()
    mock_limiter.enabled = False
    mock_limiter._check_request_limit = MagicMock()
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

    # Create a custom rate limit exception handler
    def mock_rate_limit_handler(request, exc):
        from starlette.responses import JSONResponse

        return JSONResponse(
            {"error": f"Rate limit exceeded: {exc.detail}"}, status_code=429
        )

    # Override the rate limit exception handler
    app.exception_handlers[RateLimitExceeded] = mock_rate_limit_handler

    # Add SlowAPI middleware
    app.add_middleware(SlowAPIMiddleware)

    # Note: We deliberately DO NOT add HTTPSRedirectMiddleware for tests
    # This prevents the 307 redirect issues

    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request, call_next):
        """Add security headers to all responses."""
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        return response

    # Request ID middleware for tracking
    @app.middleware("http")
    async def add_request_id(request, call_next):
        """Add request ID for tracking and debugging."""
        import uuid

        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # Set all CORS enabled origins
    if test_settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[
                str(origin) for origin in test_settings.BACKEND_CORS_ORIGINS
            ],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Override database dependency
    app.dependency_overrides[get_db] = override_get_db

    # Include router
    app.include_router(api_router, prefix=test_settings.API_V1_STR)

    # Add health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint - no rate limiting or authentication required."""
        return {
            "status": "healthy",
            "version": "2.0.0",
        }

    # Ensure token cleanup scheduler is stopped during tests
    if token_cleanup_scheduler.is_running:
        token_cleanup_scheduler.stop_scheduler()

    # Store cleanup function
    def cleanup():
        # Clear dependency overrides
        app.dependency_overrides.clear()
        # Restore original settings
        config_module.settings = original_settings

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
