"""Command execution module, used for things like curl PoC reproduction,
netcat checks, or any ad-hoc command the operator explicitly requests.
Always denylist-checked; always captured as evidence; timeout-bounded."""
from __future__ import annotations

import shlex
import subprocess
import time

from ..config import Config
from ..evidence import EvidenceStore
from ..guardrails import check_command_denylist


def run_command(
    store: EvidenceStore, cfg: Config, run_id: str, target: str, command: str,
    stage: str = "exec",
) -> tuple[int, str, int]:
    check_command_denylist(command)
    started = time.time()
    try:
        proc = subprocess.run(
            shlex.split(command), capture_output=True, text=True,
            timeout=cfg.limits.max_exec_seconds, check=False,
        )
        output = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
        exit_code = proc.returncode
    except FileNotFoundError:
        output = f"[error] command not found: {command}"
        exit_code = 127
    except subprocess.TimeoutExpired:
        output = f"[error] command timed out after {cfg.limits.max_exec_seconds}s"
        exit_code = 124

    eid = store.add_evidence(
        run_id=run_id, target=target, stage=stage, tool="shell", command=command,
        raw_output=output, exit_code=exit_code, started_at=started,
        finished_at=time.time(), tags=["exec"],
    )
    return eid, output, exit_code
