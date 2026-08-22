from __future__ import annotations
import time
from pathlib import Path
from ..config import Config
from ..evidence import EvidenceStore
from ._run import run_and_capture


def capture(
    store: EvidenceStore, cfg: Config, run_id: str, target: str,
    iface: str, bpf_filter: str, duration_seconds: int, out_dir: Path,
) -> tuple[int, str, str]:
    """Capture packets to a .pcap file for `duration_seconds`, and also store
    a text summary (tshark -r) as evidence. Requires appropriate local
    capture permissions (CAP_NET_RAW / running as a user in the wireshark
    group) — SPY-3697 does not attempt to escalate privileges itself."""
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = out_dir / f"capture_{int(time.time())}.pcap"
    argv = [
        cfg.tools.tshark_path, "-i", iface, "-a", f"duration:{duration_seconds}",
        "-f", bpf_filter, "-w", str(pcap_path),
    ]
    eid, output, _ = run_and_capture(
        store, run_id, target, stage="pcap", tool="tshark", argv=argv,
        tags=["packet-capture"], timeout=duration_seconds + 30,
    )

    summary = ""
    if pcap_path.exists():
        summary_argv = [cfg.tools.tshark_path, "-r", str(pcap_path), "-q", "-z", "conv,ip"]
        _, summary, _ = run_and_capture(
            store, run_id, target, stage="pcap", tool="tshark-summary", argv=summary_argv,
            tags=["packet-capture", "summary"], timeout=60,
        )
    return eid, str(pcap_path), summary
