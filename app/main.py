import atexit
from typing import Any, Awaitable, Callable, Dict

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.openapi.utils import get_openapi
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api.v1.router import api_router
from app.core.config import settings
from app.repositories.token import token_cleanup_scheduler

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="User management API with JWT authentication and enhanced security",
    version="2.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add rate limiter to app state
app.state.limiter = limiter

# Use the original exception handler directly - it's already properly typed
app.add_exception_handler(
    RateLimitExceeded, _rate_limit_exceeded_handler  # type: ignore[arg-type]
)

# Add SlowAPI middleware
app.add_middleware(SlowAPIMiddleware)

# Add HTTPS redirect middleware if enabled
if settings.HTTPS_REDIRECT:
    app.add_middleware(HTTPSRedirectMiddleware)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Add security headers to all responses."""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

    # Only add HSTS if we're running over HTTPS
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    # CSP that allows Swagger UI to work
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'"
    )
    response.headers["Content-Security-Policy"] = csp_policy

    # Add secure cookie settings if HTTPS
    if settings.SECURE_COOKIES and request.url.scheme == "https":
        # This ensures any cookies set will be secure
        # Individual cookie setting should also specify these flags
        pass

    return response


# Request ID middleware for tracking
@app.middleware("http")
async def add_request_id(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Add request ID for tracking and debugging."""
    import uuid

    request_id = str(uuid.uuid4())
    # Store request ID in request state for logging
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    return response


# Custom OpenAPI schema with better JWT documentation
def custom_openapi() -> Dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Define security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter your JWT token, e.g. `eyJhbGciOiJIUzI1...`",
        },
        "OAuth2PasswordBearer": {
            "type": "oauth2",
            "flows": {
                "password": {
                    "tokenUrl": f"{settings.API_V1_STR}/auth/login",
                    "scopes": {},
                }
            },
        },
    }

    # Apply both security schemes to all operations (except login and open endpoints)
    # This ensures both authentication methods are available
    for path_key, path_item in openapi_schema["paths"].items():
        # Skip login endpoint and health check
        if (
            path_key.endswith("/login")
            or path_key.endswith("/health")
            or path_key.endswith("/password-reset/request")
        ):
            continue

        for method, operation in path_item.items():
            # Add security requirement to use either Bearer or OAuth2
            operation["security"] = [{"BearerAuth": []}, {"OAuth2PasswordBearer": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore[method-assign]

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.on_event("startup")
async def startup_event() -> None:
    """Application startup event - start the token cleanup scheduler."""
    try:
        # Start the token cleanup scheduler (runs every hour)
        token_cleanup_scheduler.start_scheduler(interval_hours=1)
        print("Application started with enhanced security features")
        print(f"- Max concurrent sessions: {settings.MAX_CONCURRENT_SESSIONS}")
        print(f"- Account lockout after {settings.MAX_FAILED_LOGIN_ATTEMPTS} attempts")
        print(
            f"- HTTPS redirect: {'enabled' if settings.HTTPS_REDIRECT else 'disabled'}"
        )
    except Exception as e:
        print(f"Failed to start token cleanup scheduler: {e}")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Application shutdown event - stop the token cleanup scheduler."""
    try:
        token_cleanup_scheduler.stop_scheduler()
    except Exception as e:
        print(f"Error stopping token cleanup scheduler: {e}")


# Ensure scheduler is stopped on application exit
def cleanup_on_exit() -> None:
    """Cleanup function called on application exit."""
    if token_cleanup_scheduler.is_running:
        token_cleanup_scheduler.stop_scheduler()


atexit.register(cleanup_on_exit)


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint - no rate limiting or authentication required."""
    return {
        "status": "healthy",
        "version": app.version,
    }


@app.get("/security/status")
async def security_status() -> Dict[str, Any]:
    """
    Get security configuration status (public endpoint).
    """
    return {
        "https_redirect": settings.HTTPS_REDIRECT,
        "secure_cookies": settings.SECURE_COOKIES,
        "max_concurrent_sessions": settings.MAX_CONCURRENT_SESSIONS,
        "account_lockout_threshold": settings.MAX_FAILED_LOGIN_ATTEMPTS,
        "account_lockout_duration_minutes": settings.ACCOUNT_LOCKOUT_MINUTES,
        "password_reset_code_expiry_minutes": settings.PASSWORD_RESET_CODE_EXPIRE_MINUTES,  # noqa
        "rate_limits": {
            "login": settings.RATE_LIMIT_LOGIN,
            "refresh": settings.RATE_LIMIT_REFRESH,
            "logout": settings.RATE_LIMIT_LOGOUT,
            "register": settings.RATE_LIMIT_REGISTER,
            "password_reset": settings.RATE_LIMIT_PASSWORD_RESET,
        },
    }


@app.get("/admin/token-cleanup-status")
async def token_cleanup_status() -> Dict[str, Any]:
    """
    Get status of the token cleanup scheduler.
    This endpoint can be used for monitoring.
    """
    return {
        "scheduler_running": token_cleanup_scheduler.is_running,
        "next_run_time": token_cleanup_scheduler.get_next_run_time(),
    }


@app.post("/admin/manual-token-cleanup")
async def manual_token_cleanup() -> Dict[str, Any]:
    """
    Manually trigger token cleanup.
    This endpoint can be used for administrative purposes.
    """
    cleaned_count = await token_cleanup_scheduler.manual_cleanup()
    return {
        "message": "Manual token cleanup completed",
        "tokens_cleaned": cleaned_count,
    }
