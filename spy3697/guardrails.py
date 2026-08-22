"""Hard safety gate. Every active module (recon, scan, verify, pcap, exec) must
call `require_authorization()` before doing anything against a network target.

This is intentionally NOT bypassable by the LLM: the LLM never sees or controls
this check, it happens in plain Python before any tool subprocess is spawned.
"""
from __future__ import annotations

from .config import Config


class AuthorizationError(RuntimeError):
    pass


def require_authorization(cfg: Config, target: str, confirmed_by_user: bool) -> None:
    """Raise AuthorizationError unless the target is on the allow-list, or the
    caller has explicitly confirmed authorization for this run (CLI flag /
    web UI checkbox), which is logged alongside every evidence record.
    """
    if cfg.is_authorized(target):
        return
    if confirmed_by_user:
        return
    raise AuthorizationError(
        f"'{target}' is not in authorized_targets in config.yaml and this run did not pass "
        f"an explicit authorization confirmation. Add it to config.yaml, or re-run with "
        f"--i-confirm-authorization (CLI) / check the authorization box (web UI). "
        f"Only do this for systems you own or are explicitly permitted to test."
    )


def require_active_allowed(cfg: Config, target: str) -> None:
    """Passive-only targets can be recon'd via OSINT but never actively scanned,
    exploited, or have commands executed against them."""
    if cfg.is_passive_only(target):
        raise AuthorizationError(
            f"'{target}' is marked passive_only_targets in config.yaml — active scanning, "
            f"verification, and exec are disabled for it."
        )


# Commands the shell_exec wrapper will always refuse, regardless of confirmation,
# because they have no legitimate place in a scoped pentest workflow and are
# common indicators of scope creep or destructive intent.
DENYLIST_SUBSTRINGS = [
    "rm -rf /",
    "mkfs",
    ":(){ :|:& };:",  # fork bomb
    "dd if=/dev/zero",
    "> /dev/sda",
    "shutdown",
    "reboot",
]


def check_command_denylist(command: str) -> None:
    lowered = command.lower()
    for bad in DENYLIST_SUBSTRINGS:
        if bad in lowered:
            raise AuthorizationError(f"Command blocked by denylist (matched: '{bad}').")
