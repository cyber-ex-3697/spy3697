"""Direct web access module. Used for lightweight probing (headers, robots.txt,
banner grabs) and, critically, for capturing the *exact* request/response that
proves a finding during verification — this becomes the PoC.
"""
from __future__ import annotations

import ssl
import time
import socket
from typing import Optional

import requests

from ..evidence import EvidenceStore


def http_get(
    store: EvidenceStore, run_id: str, target: str, url: str,
    stage: str = "recon", headers: Optional[dict] = None, timeout: int = 15,
    verify_tls: bool = False, allow_redirects: bool = True,
) -> tuple[int, requests.Response | None, str]:
    """GET a URL, store the raw request+response as evidence. Returns
    (evidence_id, response_or_None, raw_text)."""
    started = time.time()
    req_line = f"GET {url}\nHeaders: {headers or {}}"
    try:
        resp = requests.get(
            url, headers=headers, timeout=timeout, verify=verify_tls,
            allow_redirects=allow_redirects,
        )
        raw = (
            f"> {req_line}\n\n"
            f"< HTTP {resp.status_code}\n"
            f"< Headers: {dict(resp.headers)}\n\n"
            f"< Body (first 4000 chars):\n{resp.text[:4000]}"
        )
        exit_code = 0
    except requests.RequestException as e:
        resp = None
        raw = f"> {req_line}\n\n[error] {e!r}"
        exit_code = 1

    eid = store.add_evidence(
        run_id=run_id, target=target, stage=stage, tool="http",
        command=f"GET {url}", raw_output=raw, exit_code=exit_code,
        started_at=started, finished_at=time.time(), tags=["web"],
    )
    return eid, resp, raw


def http_request(
    store: EvidenceStore, run_id: str, target: str, method: str, url: str,
    stage: str = "verify", headers: Optional[dict] = None, data=None, params=None,
    timeout: int = 15, verify_tls: bool = False,
) -> tuple[int, requests.Response | None, str]:
    """General request (used during verification, e.g. to reproduce an
    injection payload). Stores the exact reproduction as evidence — this raw
    record is what the PoC script is generated from."""
    started = time.time()
    req_desc = f"{method.upper()} {url}\nHeaders: {headers or {}}\nParams: {params}\nData: {data}"
    try:
        resp = requests.request(
            method, url, headers=headers, data=data, params=params,
            timeout=timeout, verify=verify_tls,
        )
        raw = (
            f"> {req_desc}\n\n"
            f"< HTTP {resp.status_code}\n"
            f"< Headers: {dict(resp.headers)}\n\n"
            f"< Body (first 4000 chars):\n{resp.text[:4000]}"
        )
        exit_code = 0
    except requests.RequestException as e:
        resp = None
        raw = f"> {req_desc}\n\n[error] {e!r}"
        exit_code = 1

    eid = store.add_evidence(
        run_id=run_id, target=target, stage=stage, tool="http",
        command=req_desc.replace("\n", " | "), raw_output=raw, exit_code=exit_code,
        started_at=started, finished_at=time.time(), tags=["web", "verification"],
    )
    return eid, resp, raw


def tls_cert_info(store: EvidenceStore, run_id: str, target: str, port: int = 443) -> tuple[int, str]:
    started = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                cipher = ssock.cipher()
        raw = f"cert={cert}\ncipher={cipher}"
        exit_code = 0
    except Exception as e:  # noqa: BLE001
        raw = f"[error] {e!r}"
        exit_code = 1
    eid = store.add_evidence(
        run_id=run_id, target=target, stage="recon", tool="tls",
        command=f"TLS handshake {target}:{port}", raw_output=raw, exit_code=exit_code,
        started_at=started, finished_at=time.time(), tags=["tls"],
    )
    return eid, raw
