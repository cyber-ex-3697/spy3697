"""XSS detection via dalfox — a real, established open-source XSS scanner
(github.com/hahwul/dalfox). Like sqlmap/nuclei, this is an existing
purpose-built tool being wrapped, not novel payload code authored here.
dalfox only reports a finding when it observes its probe actually reflected
or executed in the response, so hits are grounded in real server behavior."""
from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def scan_url(store: EvidenceStore, cfg: Config, run_id: str, target_url: str,
             cookie: str | None = None) -> tuple[int, str]:
    argv = [cfg.tools.dalfox_path, "url", target_url, "--silence", "--format", "json"]
    if cookie:
        argv += ["--cookie", cookie]
    eid, output, _ = run_and_capture(
        store, run_id, target_url, stage="identify", tool="dalfox", argv=argv,
        tags=["xss"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
