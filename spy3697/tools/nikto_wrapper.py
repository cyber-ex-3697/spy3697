"""Web server vulnerability scanning via nikto — a long-established
open-source scanner (github.com/sullo/nikto) that checks for outdated
server software, dangerous files/CGIs, default credentials, and known
server misconfigurations. Complements nuclei: nikto's checks are broader
but less precise (more false positives), so its output is stored as
'identify'-stage evidence and, like everything else, treated as candidate
until independently re-verified."""
from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def scan(store: EvidenceStore, cfg: Config, run_id: str, target: str,
          port: int = 80, ssl: bool = False) -> tuple[int, str]:
    argv = [cfg.tools.nikto_path, "-h", target, "-p", str(port), "-Format", "txt", "-ask", "no"]
    if ssl:
        argv += ["-ssl"]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="identify", tool="nikto", argv=argv,
        tags=["vuln-scan", "web"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
