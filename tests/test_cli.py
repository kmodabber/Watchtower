import pytest

from watchtower.cli import main


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "watchtower" in capsys.readouterr().out
