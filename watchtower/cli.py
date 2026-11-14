"""The watchtower command line entry point.

Subcommands so far: db upgrade, db seed, web. Later tickets add scan, consent and scanner.
"""

import argparse
import logging
from collections.abc import Sequence

from watchtower.store.db import DEFAULT_DB_PATH

log = logging.getLogger("watchtower")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchtower", description="Home network watchtower.")
    sub = parser.add_subparsers(dest="command", title="commands", metavar="<command>")

    db = sub.add_parser("db", help="create, migrate or seed the database")
    db_sub = db.add_subparsers(dest="db_command", required=True, metavar="<action>")
    for name, text in (
        ("upgrade", "apply every migration (creates the database if missing)"),
        ("seed", "fill an empty dev database from the lab fixtures"),
    ):
        p = db_sub.add_parser(name, help=text)
        p.add_argument("--db", default=str(DEFAULT_DB_PATH), help="database file (%(default)s)")

    web = sub.add_parser("web", help="run the web service (API and dashboard)")
    web.add_argument("--db", default=str(DEFAULT_DB_PATH), help="database file (%(default)s)")
    # Localhost by default: only open it to the LAN on purpose (e.g. on the Pi).
    web.add_argument("--host", default="127.0.0.1", help="address to bind (%(default)s)")
    web.add_argument("--port", type=int, default=8000, help="port (%(default)s)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "db":
        if args.db_command == "upgrade":
            from watchtower.store.db import upgrade

            upgrade(args.db)
            log.info("Database %s is up to date", args.db)
        else:
            from watchtower.store.seed import SeedError, seed

            try:
                count = seed(args.db)
            except SeedError as e:
                log.error("%s", e)
                return 1
            log.info("Seeded %s with %d devices", args.db, count)
    elif args.command == "web":
        import uvicorn

        from watchtower.api.app import create_app
        from watchtower.store.db import upgrade

        upgrade(args.db)
        uvicorn.run(create_app(args.db), host=args.host, port=args.port)
    else:
        parser.print_help()
    return 0
