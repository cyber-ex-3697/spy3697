from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def test_url(store: EvidenceStore, cfg: Config, run_id: str, target_url: str,
             data: str | None = None, level: int = 1, risk: int = 1,
             batch: bool = True) -> tuple[int, str]:
    """Run sqlmap against a single URL/param to confirm (not blind-guess) SQL
    injection. level/risk default low to stay non-destructive; raise only
    with explicit user intent for a deeper authorized test."""
    argv = [cfg.tools.sqlmap_path, "-u", target_url, "--level", str(level), "--risk", str(risk)]
    if data:
        argv += ["--data", data]
    if batch:
        argv += ["--batch"]
    argv += ["--output-dir=/tmp/spy3697_sqlmap"]
    eid, output, _ = run_and_capture(
        store, run_id, target_url, stage="verify", tool="sqlmap", argv=argv,
        tags=["sqli", "verification"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
