import secrets
from typing import List, Optional

from pydantic import AnyHttpUrl, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "User Management API"

    # ENVIRONMENT
    ENVIRONMENT: str = "development"  # development, staging, production

    # SECURITY
    SECRET_KEY: str  # Required, will raise error if not in environment
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # 30 minutes
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # 7 days
    ALGORITHM: str = "HS256"

    # HTTPS and Cookie Security
    HTTPS_REDIRECT: bool = False  # Default to False for development
    SECURE_COOKIES: bool = False  # Default to False for development

    # Session Management
    MAX_CONCURRENT_SESSIONS: int = 5  # Maximum concurrent sessions per user
    SESSION_EXPIRE_DAYS: int = 30  # Session expiration in days

    # Account Security
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5  # Failed attempts before lockout
    ACCOUNT_LOCKOUT_MINUTES: int = 15  # Account lockout duration

    # Password Reset
    PASSWORD_RESET_CODE_EXPIRE_MINUTES: int = 15  # Password reset code expiry

    # Password settings
    ARGON2_TIME_COST: int = 2
    ARGON2_MEMORY_COST: int = 102400
    ARGON2_PARALLELISM: int = 8
    ARGON2_HASH_LENGTH: int = 16
    ARGON2_SALT_LENGTH: int = 16

    # Rate Limiting Configuration
    RATE_LIMIT_LOGIN: str = "5/minute"  # Login attempts per minute per IP
    RATE_LIMIT_REFRESH: str = "10/minute"  # Token refresh per minute per IP
    RATE_LIMIT_LOGOUT: str = "20/minute"  # Logout attempts per minute per IP
    RATE_LIMIT_REGISTER: str = "3/minute"  # User registration per minute per IP
    RATE_LIMIT_LIST_USERS: str = "30/minute"  # User listing per minute per IP
    RATE_LIMIT_PASSWORD_RESET: str = "3/minute"  # Password reset per minute per IP
    RATE_LIMIT_PASSWORD_RESET_CONFIRM: str = (
        "5/minute"  # Password reset confirm per minute per IP
    )

    # Testing flag - when True, rate limiting is disabled
    TESTING: bool = False

    # CORS - Changed to str to avoid JSON parsing issues
    BACKEND_CORS_ORIGINS: str = ""

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate that the secret key is secure."""
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        if v in ["test-secret-key", "your-secret-key", "change-me", "secret"]:
            raise ValueError("Cannot use default or weak secret key in production")
        return v

    @field_validator("BACKEND_CORS_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: str) -> List[AnyHttpUrl]:
        """Parse CORS origins from string to list of URLs."""
        if not v:
            return []

        # Handle both comma-separated and JSON array formats
        if v.startswith("[") and v.endswith("]"):
            # JSON array format: ["http://localhost:3000", "http://localhost:8000"]
            import json

            origins = json.loads(v)
        else:
            # Comma-separated format: http://localhost:3000,http://localhost:8000
            origins = [origin.strip() for origin in v.split(",") if origin.strip()]

        # Convert to AnyHttpUrl objects
        return [AnyHttpUrl(origin) for origin in origins]

    # DATABASE - Support both combined and separate host/port formats
    # Combined format (original)
    POSTGRES_SERVER: Optional[str] = None
    # Separate format
    POSTGRES_HOST: Optional[str] = None
    POSTGRES_PORT: Optional[str] = None
    # Common fields
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    DATABASE_URI: Optional[PostgresDsn] = None

    # Use model_validator instead of field_validator for complex validation across fields # noqa
    @model_validator(mode="after")
    def assemble_db_connection(self) -> "Settings":
        if not self.DATABASE_URI:
            # Determine host and port from either POSTGRES_SERVER or POSTGRES_HOST/POSTGRES_PORT # noqa
            host = None
            port = None

            if self.POSTGRES_SERVER:
                server_parts = self.POSTGRES_SERVER.split(":")
                host = server_parts[0]
                port = server_parts[1] if len(server_parts) > 1 else "5432"
            elif self.POSTGRES_HOST:
                host = self.POSTGRES_HOST
                port = self.POSTGRES_PORT or "5432"
            else:
                raise ValueError(
                    "Either POSTGRES_SERVER or POSTGRES_HOST must be provided"
                )

            # Convert port to integer
            port_int = int(port)

            # Build the database URI
            self.DATABASE_URI = PostgresDsn.build(
                scheme="postgresql+asyncpg",
                username=self.POSTGRES_USER,
                password=self.POSTGRES_PASSWORD,
                host=host,
                port=port_int,  # Pass as integer
                path=self.POSTGRES_DB,
            )
        return self

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        """Validate security settings for production."""
        # Only enforce strict security in production environment
        if self.ENVIRONMENT == "production":
            if not self.HTTPS_REDIRECT:
                raise ValueError("HTTPS_REDIRECT must be True in production")
            if not self.SECURE_COOKIES:
                raise ValueError("SECURE_COOKIES must be True in production")
            if self.SECRET_KEY in ["your-super-secret-key-change-this-in-production"]:
                raise ValueError("Must change default SECRET_KEY in production")
        return self

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"  # Allow extra fields in settings


def generate_secret_key() -> str:
    """Generate a cryptographically secure secret key."""
    return secrets.token_urlsafe(32)  # 256-bit key


# Create a default settings instance that can be imported
# This will use environment variables or .env file
# NEVER silently fallback to testing mode - fail fast in production
settings = Settings()  # type: ignore[call-arg]
