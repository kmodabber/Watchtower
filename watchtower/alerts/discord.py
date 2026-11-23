"""Send one plain-text message to a Discord webhook (WT-68, WT-FR-17, PRD T-09, C5).

send() never raises: a failed alert must not fail the scan. The webhook URL is a secret, so
it is never logged. Only a status code or an exception's class name is, because httpx error
messages can include the URL.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable

try:
    import httpx
except ModuleNotFoundError:  # the lab scanner image has no httpx; scans must still work
    httpx = None

log = logging.getLogger(__name__)

# httpx logs every request URL at INFO, which would put the webhook in our logs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

MAX_LENGTH = 2000  # Discord's limit for one message
MAX_RETRY_WAIT = 30.0
DEFAULT_RETRY_WAIT = 1.0  # when a 429 does not say how long to wait
TIMEOUT_SECONDS = 10


def fit_message(text: str, *, keep_last: int = 0) -> str:
    """Cut whole lines so text fits one message, ending the cut with "…and N more".

    `keep_last` lines at the end (e.g. the Details link) are kept after that marker.
    """
    if len(text) <= MAX_LENGTH:
        return text
    lines = text.split("\n")
    split = len(lines) - keep_last
    body, tail = lines[:split], lines[split:]
    # Reserve room for the longest marker we could need, plus the newlines around it.
    room = MAX_LENGTH - len(f"…and {len(body)} more") - sum(len(line) + 1 for line in tail)
    kept: list[str] = []
    used = 0
    for line in body:
        used += len(line) + 1
        if used > room:
            break
        kept.append(line)
    return "\n".join([*kept, f"…and {len(body) - len(kept)} more", *tail])


def _seconds(value: object) -> float | None:
    """A usable wait in seconds, or None for a missing or nonsense value."""
    try:
        seconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return seconds if math.isfinite(seconds) and seconds >= 0 else None


def _retry_wait(response: httpx.Response) -> float:
    """How long Discord asked us to wait: JSON body first, then the Retry-After header."""
    try:
        body = response.json()
    except ValueError:
        body = None
    wait = _seconds(body.get("retry_after")) if isinstance(body, dict) else None
    if wait is None:
        wait = _seconds(response.headers.get("Retry-After"))
    return min(DEFAULT_RETRY_WAIT if wait is None else wait, MAX_RETRY_WAIT)


def _post(webhook_url: str, content: str) -> httpx.Response | None:
    try:
        return httpx.post(
            webhook_url,
            json={"content": content, "username": "Watchtower"},
            timeout=TIMEOUT_SECONDS,
        )
    except Exception as exc:  # includes httpx.InvalidURL, which is not an httpx.HTTPError
        log.warning("Discord alert not sent: %s", type(exc).__name__)
        return None


def send(webhook_url: str, text: str, *, sleep: Callable[[float], None] | None = None) -> bool:
    """Post text to the webhook. True on 2xx; a 429 is waited out and retried once."""
    if httpx is None:
        log.warning("Discord alert not sent: httpx is not installed")
        return False
    content = fit_message(text)
    response = _post(webhook_url, content)
    if response is not None and response.status_code == 429:
        (sleep or time.sleep)(_retry_wait(response))
        response = _post(webhook_url, content)
    if response is None:
        return False
    if 200 <= response.status_code < 300:
        return True
    log.warning("Discord alert not sent: HTTP %s", response.status_code)
    return False
