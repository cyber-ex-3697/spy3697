"""Privilege-escalation enumeration assist. This does NOT escalate privileges
or exploit anything — it runs a well-known, read-only enumeration command
(you supply it; e.g. a linpeas.sh/winPEAS invocation, `sudo -l`, `find / -perm
-4000`, etc.) on a target you already have a shell/SSH session on, and
captures the output as evidence. Interpreting that output for privesc paths
is left to you or the LLM's evidence-cited analysis — this module just runs
a command and records what actually came back, same as shell_exec.py.
"""
from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ..guardrails import check_command_denylist
from .shell_exec import run_command


def run_enum_command(store: EvidenceStore, cfg: Config, run_id: str, target: str,
                      command: str) -> tuple[int, str, int]:
    """Thin wrapper over shell_exec.run_command, tagged for privesc-enum
    evidence. Example commands (run these locally, e.g. inside an SSH
    session you already have to an authorized box — this does not connect
    anywhere for you):
        sudo -l
        find / -perm -4000 -type f 2>/dev/null
        ./linpeas.sh   (if you've placed a copy of the script yourself)
    """
    check_command_denylist(command)
    return run_command(store, cfg, run_id, target, command, stage="verify")
