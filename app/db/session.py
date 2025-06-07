from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

# Create async engine for PostgreSQL
engine = create_async_engine(
    str(settings.DATABASE_URI),
    pool_pre_ping=True,
    echo=False,
    future=True,
)

# Create sessionmaker for async sessions
AsyncSessionLocal = async_sessionmaker(
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

    def __init__(self) -> None:
        self.session: Optional[AsyncSession] = None

    async def __aenter__(self) -> AsyncSession:
        self.session = AsyncSessionLocal()
        return self.session

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Optional[object],
    ) -> None:
        if self.session is None:
            return

        if exc_type is not None:
            await self.session.rollback()
        else:
            try:
                await self.session.commit()
            except Exception:
                await self.session.rollback()
                raise
        await self.session.close()
