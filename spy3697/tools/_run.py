"""Shared helper for running external CLI security tools and capturing output
into the evidence store."""
from __future__ import annotations

import shlex
import subprocess
import time
from typing import Optional

from ..evidence import EvidenceStore


def run_and_capture(
    store: EvidenceStore,
    run_id: str,
    target: str,
    stage: str,
    tool: str,
    argv: list[str],
    tags: Optional[list[str]] = None,
    timeout: int = 300,
) -> tuple[int, str, int]:
    """Run argv, capture combined stdout+stderr, store as evidence.
    Returns (evidence_id, output_text, exit_code)."""
    started = time.time()
    command_str = " ".join(shlex.quote(a) for a in argv)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        output = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
        exit_code = proc.returncode
    except FileNotFoundError:
        output = f"[error] tool binary not found for command: {command_str}"
        exit_code = 127
    except subprocess.TimeoutExpired:
        output = f"[error] command timed out after {timeout}s: {command_str}"
        exit_code = 124

    finished = time.time()
    eid = store.add_evidence(
        run_id=run_id,
        target=target,
        stage=stage,
        tool=tool,
        command=command_str,
        raw_output=output,
        exit_code=exit_code,
        started_at=started,
        finished_at=finished,
        tags=tags or [],
    )
    return eid, output, exit_code
