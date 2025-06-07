from typing import List, Optional

from pydantic import AnyHttpUrl, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "User Management API"

    # SECURITY
    SECRET_KEY: str  # Required, will raise error if not in environment
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # 30 minutes
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # 7 days
    ALGORITHM: str = "HS256"

    # Password settings
    ARGON2_TIME_COST: int = 2
    ARGON2_MEMORY_COST: int = 102400
    ARGON2_PARALLELISM: int = 8
    ARGON2_HASH_LENGTH: int = 16
    ARGON2_SALT_LENGTH: int = 16

    # CORS - Changed to str to avoid JSON parsing issues
    BACKEND_CORS_ORIGINS: str = ""

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

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"  # Allow extra fields in settings


# Create a default settings instance that can be imported
# This will use environment variables or .env file
try:
    settings = Settings()  # type: ignore[call-arg]
except Exception:
    # For testing or when env vars are not set, create a dummy instance
    # This will be overridden by test configurations
    settings = Settings(
        SECRET_KEY="test-secret-key",
        POSTGRES_USER="test",
        POSTGRES_PASSWORD="test",
        POSTGRES_DB="test",
    )  # type: ignore[call-arg]
