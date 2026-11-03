"""Engine / session helpers.

Default is an in-memory SQLite kept alive for the life of the engine (StaticPool
+ one shared connection) so sessions share the same data — convenient for tests
and demos. Pass a real URL (e.g. ``postgresql+psycopg://...`` or a sqlite file)
in production.
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base

IN_MEMORY = "sqlite+pysqlite:///:memory:"


def make_engine(url: str = IN_MEMORY, *, echo: bool = False) -> Engine:
    if url == IN_MEMORY:
        return create_engine(
            url, echo=echo, future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(url, echo=echo, future=True)


def create_all(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False, future=True)


def init_db(url: str = IN_MEMORY, *, echo: bool = False) -> sessionmaker[Session]:
    """Create the engine, build the schema, and return a session factory."""
    engine = make_engine(url, echo=echo)
    create_all(engine)
    return make_session_factory(engine)
