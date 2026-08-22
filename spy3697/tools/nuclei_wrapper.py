from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def scan(store: EvidenceStore, cfg: Config, run_id: str, target_url: str,
          severity: str = "info,low,medium,high,critical", tags: str | None = None) -> tuple[int, str]:
    """Run nuclei's community template set against a URL. nuclei only fires
    templates that actively probe+confirm a match server-side, so hits here
    are already 'observed', not guessed — still treated as candidates until
    the orchestrator verifies them."""
    argv = [cfg.tools.nuclei_path, "-u", target_url, "-severity", severity, "-jsonl", "-silent"]
    if tags:
        argv += ["-tags", tags]
    eid, output, _ = run_and_capture(
        store, run_id, target_url, stage="identify", tool="nuclei", argv=argv,
        tags=["vuln-scan"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
