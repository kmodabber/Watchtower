"""The only place Watchtower builds an Nmap command (WT-FR-12, T-11).

``build_command`` returns argv for ``subprocess.run(..., shell=False)``.
It never returns a shell string. The NSE allowlist is empty, so ``--script``
is never added. Later allowlist work should import this function instead of
assembling flags on its own.
"""

from __future__ import annotations

# Gentle profiles. Nothing else may be appended, including --script.
_PROFILE_FLAGS: dict[str, tuple[str, ...]] = {
    "quick": ("-sn", "--privileged"),
    "full": (
        "-sS",
        "-sV",
        "--version-light",
        "--top-ports",
        "1000",
        "-T3",
        "--max-rate",
        "100",
        "--host-timeout",
        "5m",
        "--privileged",
    ),
}

PROFILES: tuple[str, ...] = tuple(_PROFILE_FLAGS)


def require_argv_token(name: str, value: object) -> str:
    """Require one argv element: non-empty, no leading dash, no whitespace."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    if value.startswith("-") or any(char.isspace() for char in value):
        raise ValueError(f"{name} must be a host or subnet, not nmap options")
    return value


def build_command(profile: str, network: str, exclude_ip: str) -> list[str]:
    """Build the Nmap argv for ``profile``.

    ``network`` and ``exclude_ip`` each become one argument. ``exclude_ip``
    is required and is always passed as ``--exclude``.

    Raises
    ------
    ValueError
        Unknown profile, or a network / exclude_ip that is not one argv token.
        No command list is returned in that case.
    """
    if profile not in _PROFILE_FLAGS:
        raise ValueError(f"profile must be 'quick' or 'full', got {profile!r}")
    network_arg = require_argv_token("network", network)
    exclude_arg = require_argv_token("exclude_ip", exclude_ip)
    flags = _PROFILE_FLAGS[profile]
    return ["nmap", *flags, "-oX", "-", "--exclude", exclude_arg, network_arg]
