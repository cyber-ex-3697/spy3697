from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def port_scan(store: EvidenceStore, cfg: Config, run_id: str, target: str,
              ports: str | None = None, service_detect: bool = True) -> tuple[int, str]:
    argv = [cfg.tools.nmap_path, "-Pn"]
    if service_detect:
        argv += ["-sV", "-sC"]
    if ports:
        argv += ["-p", ports]
    else:
        argv += ["--top-ports", "1000"]
    argv += [target]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="recon", tool="nmap", argv=argv,
        tags=["port-scan"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
