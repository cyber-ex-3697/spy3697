"""Supply-chain / dependency vulnerability scanning via trivy — a real,
established open-source SCA scanner (github.com/aquasecurity/trivy). This
scans a filesystem path, container image, or SBOM for known-vulnerable
dependencies (the same category of issue as the SolarWinds/3CX incidents:
a compromised or outdated upstream component), matching against public
vulnerability databases. Requires local access to the code/image/manifest —
this is not something you can point at an arbitrary remote URL."""
from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def scan_filesystem(store: EvidenceStore, cfg: Config, run_id: str, target: str,
                     path: str, severity: str = "MEDIUM,HIGH,CRITICAL") -> tuple[int, str]:
    argv = [cfg.tools.trivy_path, "fs", "--severity", severity, "--format", "json", path]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="identify", tool="trivy-fs", argv=argv,
        tags=["supply-chain", "sca"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output


def scan_image(store: EvidenceStore, cfg: Config, run_id: str, target: str,
                image: str, severity: str = "MEDIUM,HIGH,CRITICAL") -> tuple[int, str]:
    argv = [cfg.tools.trivy_path, "image", "--severity", severity, "--format", "json", image]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="identify", tool="trivy-image", argv=argv,
        tags=["supply-chain", "sca"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
