"""Database connection and migrations (WT-FR-20).

Every connection runs WAL (the scanner writes while the API reads), foreign keys on,
and a 5 s busy timeout instead of failing straight away on a locked database.
"""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import sessionmaker

DEFAULT_DB_PATH = Path("var/watchtower.db")
MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def make_engine(db_path: str | Path = DEFAULT_DB_PATH) -> Engine:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # check_same_thread off: FastAPI may use a connection from another thread.
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _record) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker:
    return sessionmaker(engine, expire_on_commit=False)


def alembic_config(db_path: str | Path = DEFAULT_DB_PATH) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{Path(db_path)}")
    return cfg


def upgrade(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """Bring the database at db_path up to the latest migration (creates it if missing)."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(db_path), "head")
