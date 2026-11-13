"""Test configuration with an isolated temporary test database.

The test database lives in the OS temp directory (never under the project
working directory and never the development database `netwatch.db`). The
`get_db` dependency is overridden so every endpoint request binds to the
isolated test session. The development `settings.DATABASE_URL` singleton is
never mutated.
"""

import os
import tempfile

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.session import Base, get_db


# Isolated temporary test database: never CWD-relative, never the dev DB.
TEST_DB_PATH = os.path.join(tempfile.gettempdir(), f"nw_test_{os.getpid()}.db")
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_PATH}"

# Fresh engine bound exclusively to the isolated test database.
test_engine = create_engine(
    TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def _override_get_db():
    """Override get_db to bind every request to the isolated test DB."""
    db = TestSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# Route all endpoint requests to the isolated test database.
app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all tables on the isolated test DB before tests; drop and cleanup after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    # Teardown: drop tables and dispose the isolated test engine.
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    try:
        if os.path.exists(TEST_DB_PATH):
            os.unlink(TEST_DB_PATH)
    except PermissionError:
        pass


@pytest_asyncio.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
