"""The watchtower command line entry point.

Subcommands so far: scan, consent, db upgrade, db seed, web. A later ticket adds scanner.
"""

import argparse
import logging
from collections.abc import Sequence

from watchtower.store.db import DEFAULT_DB_PATH

log = logging.getLogger("watchtower")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchtower", description="Home network watchtower.")
    sub = parser.add_subparsers(dest="command", title="commands", metavar="<command>")

    scan = sub.add_parser("scan", help="scan the local network once and print a report")
    scan.add_argument(
        "--profile", choices=("full", "quick"), default="full", help="scan profile (%(default)s)"
    )
    scan.add_argument(
        "--config", help="config file (default: $WATCHTOWER_CONFIG or watchtower.toml)"
    )
    scan.add_argument("--db", help="database file (default: db_path from the config)")
    scan.add_argument(
        "--fake",
        metavar="DIR",
        help="replay saved lab scans from DIR (lab-quick.xml, lab-full.xml) instead of "
        "running Nmap, e.g. tests/fixtures",
    )

    consent = sub.add_parser(
        "consent", help="confirm you own this network; no scan runs until you do"
    )
    consent.add_argument(
        "--i-own-this-network",
        action="store_true",
        required=True,
        help="I own this network, or have permission to scan it",
    )
    consent.add_argument("--db", default=str(DEFAULT_DB_PATH), help="database file (%(default)s)")

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

    if args.command == "scan":
        return _scan(args)
    if args.command == "consent":
        from watchtower.store.db import make_engine, make_sessionmaker, upgrade
        from watchtower.store.storage import confirm_ownership

        upgrade(args.db)
        engine = make_engine(args.db)
        try:
            with make_sessionmaker(engine).begin() as session:
                at = confirm_ownership(session)
        finally:
            engine.dispose()
        log.info("Ownership confirmed at %s; scans may now run", at)
    elif args.command == "db":
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


def _scan(args: argparse.Namespace) -> int:
    """watchtower scan (WT-102): guardrail, scan, identify, rules, store, report."""
    from watchtower.pipeline import NoConsent, ScanError, format_report, run_scan
    from watchtower.scanner.scan_engine import FakeEngine, NmapEngine

    if args.fake:
        # Replays a saved scan: no network, so no guardrail or config needed.
        engine = FakeEngine(args.fake)
        target = "172.28.0.0/24"
        db_path = args.db or str(DEFAULT_DB_PATH)
    else:
        from watchtower.config import ConfigError, load_config
        from watchtower.scanner.guardrail import GuardrailError, scan_scope

        try:
            config = load_config(args.config)
            # The target always comes from our own interface, never from the user (WT-74).
            network, own_ip = scan_scope(config.interface)
        except (ConfigError, GuardrailError) as e:
            log.error("Not scanning: %s", e)
            return 2
        engine = NmapEngine(exclude_ip=str(own_ip))
        target = str(network)
        db_path = args.db or str(config.db_path)

    try:
        report = run_scan(engine, args.profile, target, db_path)
    except NoConsent as e:
        log.error("Not scanning: %s", e)
        return 2
    except ScanError as e:
        log.error("%s", e)
        return 1
    print(format_report(report))
    return 0


if __name__ == "__main__":  # python -m watchtower.cli scan (e.g. in the scanner container)
    raise SystemExit(main())
