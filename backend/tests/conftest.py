"""
Shared pytest fixtures.

Uses an async SQLite (aiosqlite) in-memory database so tests run without
a live PostgreSQL instance. JsonType handles JSONB→JSON dialect mapping.

All tables are dropped and recreated for each test function to avoid
UNIQUE constraint collisions between tests.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base
from app.dependencies import get_db
from app.main import app
from app.models.user import User
from app.services.auth_service import create_access_token, hash_password

# ── Async SQLite in-memory engine ────────────────────────────────────────────
ASYNC_TEST_URL = "sqlite+aiosqlite://"

test_async_engine = create_async_engine(
    ASYNC_TEST_URL,
    connect_args={"check_same_thread": False},
)

TestAsyncSessionLocal = async_sessionmaker(
    bind=test_async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def override_get_db():
    async with TestAsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Table lifecycle — recreate for every test to keep isolation ─────────────

@pytest.fixture(autouse=True)
def reset_db():
    """Drop and recreate all tables before each test."""
    import asyncio

    async def _reset():
        async with test_async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    asyncio.get_event_loop().run_until_complete(_reset())
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()


# ── Helper session for fixture data setup ────────────────────────────────────

@pytest.fixture
def db_session():
    """Sync-style fixture that creates a direct async session for test data setup."""
    import asyncio

    class SyncWrapper:
        """Wraps an async session so fixtures can call it synchronously."""

        def __init__(self):
            self._loop = asyncio.new_event_loop()
            self._session: AsyncSession = self._loop.run_until_complete(
                TestAsyncSessionLocal().__aenter__()
            )

        def add(self, obj):
            self._session.add(obj)

        def commit(self):
            self._loop.run_until_complete(self._session.commit())

        def refresh(self, obj):
            self._loop.run_until_complete(self._session.refresh(obj))

        def close(self):
            self._loop.run_until_complete(self._session.__aexit__(None, None, None))
            self._loop.close()

    wrapper = SyncWrapper()
    try:
        yield wrapper
        wrapper.commit()
    except Exception:
        pass
    finally:
        wrapper.close()


# ── Client ───────────────────────────────────────────────────────────────────

@pytest.fixture
def client(reset_db):
    with TestClient(app) as c:
        yield c


# ── User fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def admin_user(db_session):
    user = User(
        id="test-admin-000000000000000000001",
        username="testadmin",
        email="testadmin@test.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def analyst_user(db_session):
    user = User(
        id="test-analyst-0000000000000000002",
        username="testanalyst",
        email="testanalyst@test.local",
        hashed_password=hash_password("Analyst@1234"),
        role="analyst",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def viewer_user(db_session):
    user = User(
        id="test-viewer-000000000000000000001",
        username="testviewer",
        email="testviewer@test.local",
        hashed_password=hash_password("Viewer@1234"),
        role="viewer",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_token(admin_user):
    return create_access_token({"sub": admin_user.id, "role": admin_user.role})


@pytest.fixture
def analyst_token(analyst_user):
    return create_access_token({"sub": analyst_user.id, "role": analyst_user.role})


@pytest.fixture
def viewer_token(viewer_user):
    return create_access_token({"sub": viewer_user.id, "role": viewer_user.role})


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
