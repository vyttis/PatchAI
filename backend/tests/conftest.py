"""Shared test fixtures — in-memory async SQLite for unit tests.

SQLite doesn't support JSONB, ARRAY, or Computed columns natively.
We register custom type compilation rules so SQLAlchemy can create
tables in SQLite for testing.
"""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import JSON, Text, event
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.schema import CreateColumn

from backend.app.database import Base

# Import all models to register them with Base.metadata
import backend.app.models  # noqa: F401


# ---------------------------------------------------------------------------
# SQLite compatibility: render PostgreSQL types as SQLite equivalents
# ---------------------------------------------------------------------------

@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@compiles(ARRAY, "sqlite")
def _compile_array_sqlite(type_, compiler, **kw):
    return "JSON"


@compiles(CreateColumn, "sqlite")
def _skip_computed_columns_sqlite(element, compiler, **kw):
    """Skip Computed columns for SQLite — it doesn't support GENERATED with interval."""
    col = element.element
    if getattr(col, "computed", None) is not None:
        return None
    return compiler.visit_create_column(element, **kw)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def async_engine():
    """Create an async SQLite engine for testing."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db(async_engine) -> AsyncSession:
    """Yield a session bound to the test engine."""
    session_factory = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


@pytest.fixture
def org_id():
    return uuid.uuid4()


@pytest.fixture
def user_id():
    return uuid.uuid4()
