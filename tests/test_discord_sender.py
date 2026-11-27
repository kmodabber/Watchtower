"""WT-68 (WT-FR-17, PRD T-09, C5): the Discord sender. No network, no real sleeping."""

import logging
from collections.abc import Callable

import httpx
import pytest

from watchtower.alerts.discord import MAX_LENGTH, MAX_RETRY_WAIT, fit_message, send

WEBHOOK = "https://discord.test/api/webhooks/123/not-a-real-token"


class _Post:
    """Stands in for httpx.post: returns or raises the prepared outcomes in order."""

    def __init__(self, *outcomes: httpx.Response | Exception) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, **kwargs: object) -> httpx.Response:
        self.calls.append((url, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _patch(monkeypatch: pytest.MonkeyPatch, *outcomes: httpx.Response | Exception) -> _Post:
    post = _Post(*outcomes)
    monkeypatch.setattr(httpx, "post", post)
    return post


def _no_sleep() -> tuple[list[float], Callable[[float], None]]:
    waits: list[float] = []
    return waits, waits.append


def test_send_posts_content_and_username(monkeypatch: pytest.MonkeyPatch) -> None:
    post = _patch(monkeypatch, httpx.Response(204))
    assert send(WEBHOOK, "hello") is True
    assert post.calls == [
        (WEBHOOK, {"json": {"content": "hello", "username": "Watchtower"}, "timeout": 10})
    ]


def test_short_message_is_unchanged() -> None:
    assert fit_message("a\nb") == "a\nb"


def test_long_message_is_cut_on_whole_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    lines = [f"line {i:03} " + "x" * 80 for i in range(100)]
    post = _patch(monkeypatch, httpx.Response(204))
    assert send(WEBHOOK, "\n".join(lines)) is True
    content = post.calls[0][1]["json"]["content"]
    assert len(content) <= MAX_LENGTH
    *kept, marker = content.split("\n")
    assert kept == lines[: len(kept)]
    assert marker == f"…and {100 - len(kept)} more"


def test_cut_can_keep_the_last_line() -> None:
    text = "\n".join(["head", *("x" * 90 for _ in range(50)), "Details: link"])
    lines = fit_message(text, keep_last=1).split("\n")
    assert len("\n".join(lines)) <= MAX_LENGTH
    assert lines[-1] == "Details: link"
    assert lines[-2].startswith("…and ")


def test_a_single_huge_line_still_fits() -> None:
    assert fit_message("x" * 5000) == "…and 1 more"


def test_429_waits_then_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    post = _patch(monkeypatch, httpx.Response(429, json={"retry_after": 1.5}), httpx.Response(204))
    waits, sleep = _no_sleep()
    assert send(WEBHOOK, "hello", sleep=sleep) is True
    assert waits == [1.5]
    assert len(post.calls) == 2


def test_429_falls_back_to_the_header(monkeypatch: pytest.MonkeyPatch) -> None:
    limited = httpx.Response(429, headers={"Retry-After": "3"}, text="slow down")
    _patch(monkeypatch, limited, httpx.Response(204))
    waits, sleep = _no_sleep()
    assert send(WEBHOOK, "hello", sleep=sleep) is True
    assert waits == [3.0]


@pytest.mark.parametrize("value", [9999, "9999"])
def test_429_wait_is_capped(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    _patch(monkeypatch, httpx.Response(429, json={"retry_after": value}), httpx.Response(204))
    waits, sleep = _no_sleep()
    send(WEBHOOK, "hello", sleep=sleep)
    assert waits == [MAX_RETRY_WAIT]


def test_second_429_gives_up(monkeypatch: pytest.MonkeyPatch) -> None:
    limited = {"retry_after": 1}
    post = _patch(monkeypatch, httpx.Response(429, json=limited), httpx.Response(429, json=limited))
    waits, sleep = _no_sleep()
    assert send(WEBHOOK, "hello", sleep=sleep) is False
    assert len(waits) == 1
    assert len(post.calls) == 2


@pytest.mark.parametrize(
    "outcome",
    [
        httpx.Response(500),
        httpx.Response(404),
        httpx.TimeoutException(f"timed out calling {WEBHOOK}"),
        httpx.ConnectError(f"cannot reach {WEBHOOK}"),
        httpx.InvalidURL(f"bad url {WEBHOOK}"),  # not an httpx.HTTPError
    ],
)
def test_failures_return_false_and_never_log_the_url(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    outcome: httpx.Response | Exception,
) -> None:
    caplog.set_level(logging.DEBUG)
    _patch(monkeypatch, outcome)
    assert send(WEBHOOK, "hello") is False
    assert "Discord alert not sent" in caplog.text
    assert WEBHOOK not in caplog.text
    assert "not-a-real-token" not in caplog.text


def test_httpx_own_request_log_does_not_leak_the_url(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A real httpx client on a fake transport: httpx logs the full URL at INFO by default.
    client = httpx.Client(transport=httpx.MockTransport(lambda _request: httpx.Response(204)))
    monkeypatch.setattr(httpx, "post", client.post)
    caplog.set_level(logging.INFO)
    assert send(WEBHOOK, "hello") is True
    client.close()
    assert "not-a-real-token" not in caplog.text
