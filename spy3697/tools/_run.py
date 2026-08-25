"""Shared helper for running external CLI security tools and capturing output
into the evidence store."""
from __future__ import annotations

import shlex
import subprocess
import time
from typing import Optional

from ..evidence import EvidenceStore

_last_call_at: float = 0.0


def _throttle(rate_limit_per_sec: int) -> None:
    """Simple pacing so scans don't hammer the target faster than
    `limits.rate_limit_requests_per_sec` in config.yaml. This is the
    legitimate way to avoid tripping a target's rate limiter/WAF during an
    authorized test — by being a well-behaved, predictable client, not by
    rotating identity to dodge a block."""
    global _last_call_at
    if rate_limit_per_sec <= 0:
        return
    min_interval = 1.0 / rate_limit_per_sec
    elapsed = time.time() - _last_call_at
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_call_at = time.time()


def run_and_capture(
    store: EvidenceStore,
    run_id: str,
    target: str,
    stage: str,
    tool: str,
    argv: list[str],
    tags: Optional[list[str]] = None,
    timeout: int = 300,
    rate_limit_per_sec: int = 0,
) -> tuple[int, str, int]:
    """Run argv, capture combined stdout+stderr, store as evidence.
    Returns (evidence_id, output_text, exit_code)."""
    _throttle(rate_limit_per_sec)
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
