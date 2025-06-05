from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

# Create async engine for PostgreSQL
engine = create_async_engine(
    str(settings.DATABASE_URI),
    pool_pre_ping=True,
    echo=False,
    future=True,
)

# Create sessionmaker for async sessions
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for database session.

    Yields:
        AsyncSession: SQLAlchemy async session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


class TransactionManager:
    """
    Context manager for transaction management.

    Use this for operations that need to happen within a single transaction.
    """

    def __init__(self):
        self.session = None

    async def __aenter__(self) -> AsyncSession:
        self.session = AsyncSessionLocal()
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.session.rollback()
        else:
            try:
                await self.session.commit()
            except Exception:
                await self.session.rollback()
                raise
        await self.session.close()
