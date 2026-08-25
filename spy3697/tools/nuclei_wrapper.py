from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture

# Default tag set covering the categories nuclei's community template repo
# actually has maintained, verified templates for. Each template only fires
# when it gets a real positive signal from the target (a matched response,
# an out-of-band callback, a version string, etc.) — these are still
# "candidate" findings until the orchestrator's verify stage re-checks them,
# never auto-accepted as fact.
#
# Category -> nuclei tag(s):
#   XSS                        -> xss
#   SSRF                       -> ssrf
#   XXE                        -> xxe
#   CSRF                       -> csrf
#   Security misconfiguration  -> misconfig, exposure, default-login
#   Command/path injection     -> rce, injection, lfi, traversal
#   Known-CVE / N-day (incl.   -> cve  (nuclei's cve/ templates include the
#     Log4Shell, post-disclosure zero-days once patched & templated)
#   Insecure deserialization   -> deserialization
#   Auth bypass                -> auth-bypass, default-login
DEFAULT_TAGS = (
    "cve,xss,ssrf,xxe,csrf,misconfig,exposure,default-login,"
    "rce,injection,lfi,traversal,deserialization,auth-bypass"
)


def scan(store: EvidenceStore, cfg: Config, run_id: str, target_url: str,
          severity: str = "info,low,medium,high,critical", tags: str | None = None) -> tuple[int, str]:
    """Run nuclei's community template set against a URL. nuclei only fires
    templates that actively probe+confirm a match server-side, so hits here
    are already 'observed', not guessed — still treated as candidates until
    the orchestrator verifies them."""
    argv = [cfg.tools.nuclei_path, "-u", target_url, "-severity", severity, "-jsonl", "-silent"]
    argv += ["-tags", tags or DEFAULT_TAGS]
    eid, output, _ = run_and_capture(
        store, run_id, target_url, stage="identify", tool="nuclei", argv=argv,
        tags=["vuln-scan"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output


def update_templates(store: EvidenceStore, cfg: Config, run_id: str, target: str) -> tuple[int, str]:
    """Pull the latest community template set before a scan — this is how
    coverage for recently-disclosed CVEs (including things like Log4Shell)
    actually stays current, rather than anything hand-maintained here."""
    argv = [cfg.tools.nuclei_path, "-update-templates"]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="recon", tool="nuclei-update", argv=argv,
        tags=["maintenance"], timeout=180,
    )
    return eid, output
