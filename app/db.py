from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session
from sqlalchemy import create_engine, text
import os
import logging
from sqlalchemy.pool import NullPool

from .config import get_database_url, settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


DB_POOL_SIZE = int(os.getenv("AUTH_DB_POOL_SIZE", "1"))
DB_MAX_OVERFLOW = int(os.getenv("AUTH_DB_MAX_OVERFLOW", "0"))
DB_POOL_TIMEOUT = int(os.getenv("AUTH_DB_POOL_TIMEOUT", "30"))
DB_POOL_RECYCLE = int(os.getenv("AUTH_DB_POOL_RECYCLE", "1800"))
DB_POOL_CLASS = (os.getenv("AUTH_DB_POOL_CLASS", "queue").strip().lower() or "queue")

# Create async engine
_engine_kwargs = {
    "echo": False,
    "future": True,
    "pool_pre_ping": True,
}

if DB_POOL_CLASS in ("null", "none"):
    _engine_kwargs["poolclass"] = NullPool
else:
    _engine_kwargs.update(
        {
            "pool_size": DB_POOL_SIZE,
            "max_overflow": DB_MAX_OVERFLOW,
            "pool_timeout": DB_POOL_TIMEOUT,
            "pool_recycle": DB_POOL_RECYCLE,
            "pool_use_lifo": True,
        }
    )

engine = create_async_engine(get_database_url(), **_engine_kwargs)

# Create async session factory
SessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_db() -> AsyncSession:
    """Dependency to get async database session."""
    async with SessionLocal() as session:
        yield session


async def check_database_connection() -> bool:
    """Test database connectivity on startup."""
    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        logger.info("✅ Database connection successful")
        return True
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        return False
