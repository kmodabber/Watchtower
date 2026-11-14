"""Alembic environment. The URL comes from alembic.ini or from watchtower.store.db.upgrade()."""

import warnings

from alembic import context
from sqlalchemy import create_engine

from watchtower.store.models import Base

config = context.config
# SQLite can't reflect expression indexes; they are hand-written in the migrations instead.
warnings.filterwarnings("ignore", message=r".*expression-based index")


def run_migrations_online() -> None:
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as conn:
        # render_as_batch: SQLite can't ALTER most things, so Alembic copies the table instead.
        context.configure(connection=conn, target_metadata=Base.metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Offline (--sql) migrations are not supported; run against a database.")
run_migrations_online()
