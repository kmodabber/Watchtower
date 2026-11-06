"""WT-93: placeholder so CI always has at least one test to run."""

import sys


def test_python_version_matches_dev_container() -> None:
    # The scanner dev container (lab/Dockerfile.scanner) is Python 3.12.
    assert sys.version_info >= (3, 12)
