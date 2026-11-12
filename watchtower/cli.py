"""The watchtower command line entry point.

Subcommands (scan, consent, scanner, web) are added by later tickets.
"""

import argparse
import logging
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchtower", description="Home network watchtower.")
    # Later tickets register their subcommands on this object.
    parser.add_subparsers(dest="command", title="commands", metavar="<command>")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    if args.command is None:
        build_parser().print_help()
    return 0
