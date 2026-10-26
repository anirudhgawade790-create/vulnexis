"""
Custom SQLAlchemy type helpers.

JsonType maps to JSONB on PostgreSQL and falls back to JSON for
SQLite (used in tests). This keeps all models free of direct
JSONB imports.
"""
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator


class JsonType(TypeDecorator):
    """
    A JSON column that stores as JSONB on PostgreSQL and as TEXT/JSON
    on other backends (e.g. SQLite used in tests).
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())
