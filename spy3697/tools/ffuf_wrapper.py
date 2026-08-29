"""Content discovery / fuzzing via ffuf — a real, established open-source
fuzzer (github.com/ffuf/ffuf), widely used alongside/instead of gobuster.
Faster and more flexible for parameter/vhost fuzzing; gobuster stays as the
default in the automatic pipeline, ffuf is available as a heavier follow-up
or for fuzzing patterns gobuster doesn't cover (query params, headers, vhosts).
"""
from __future__ import annotations
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def fuzz_paths(store: EvidenceStore, cfg: Config, run_id: str, target: str,
                base_url: str, wordlist: str | None = None,
                extensions: str | None = None) -> tuple[int, str]:
    """Directory/file fuzzing: base_url should contain FUZZ, e.g.
    'http://host/FUZZ'."""
    wl = wordlist or f"{cfg.tools.wordlist_dir}/dirb/common.txt"
    argv = [cfg.tools.ffuf_path, "-u", base_url, "-w", wl, "-of", "json", "-s"]
    if extensions:
        argv += ["-e", extensions]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="recon", tool="ffuf", argv=argv,
        tags=["content-discovery", "fuzzing"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output


def fuzz_params(store: EvidenceStore, cfg: Config, run_id: str, target: str,
                 url_with_fuzz: str, wordlist: str | None = None,
                 method: str = "GET", data: str | None = None) -> tuple[int, str]:
    """Parameter fuzzing: url_with_fuzz or data should contain FUZZ, e.g.
    'http://host/api?FUZZ=test' or --data 'user=admin&FUZZ=1'."""
    wl = wordlist or f"{cfg.tools.wordlist_dir}/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    argv = [cfg.tools.ffuf_path, "-u", url_with_fuzz, "-w", wl, "-X", method, "-of", "json", "-s"]
    if data:
        argv += ["-d", data]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="identify", tool="ffuf-params", argv=argv,
        tags=["fuzzing", "parameter-discovery"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output


def fuzz_vhosts(store: EvidenceStore, cfg: Config, run_id: str, target: str,
                 base_url: str, domain: str, wordlist: str | None = None) -> tuple[int, str]:
    """Virtual host fuzzing: sends Host: FUZZ.domain and looks for
    differently-sized responses, which can reveal hidden vhosts."""
    wl = wordlist or f"{cfg.tools.wordlist_dir}/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    argv = [
        cfg.tools.ffuf_path, "-u", base_url, "-w", wl,
        "-H", f"Host: FUZZ.{domain}", "-of", "json", "-s",
    ]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="recon", tool="ffuf-vhost", argv=argv,
        tags=["vhost-discovery"], timeout=cfg.limits.max_scan_seconds,
    )
    return eid, output
