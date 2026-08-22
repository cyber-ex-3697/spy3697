from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def dir_scan(store: EvidenceStore, cfg: Config, run_id: str, base_url: str,
             wordlist: str | None = None, extensions: str | None = None) -> tuple[int, str]:
    wl = wordlist or f"{cfg.tools.wordlist_dir}/dirb/common.txt"
    argv = [cfg.tools.gobuster_path, "dir", "-u", base_url, "-w", wl, "-q"]
    if extensions:
        argv += ["-x", extensions]
    eid, output, _ = run_and_capture(
        store, run_id, base_url, stage="recon", tool="gobuster", argv=argv,
        tags=["content-discovery"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
