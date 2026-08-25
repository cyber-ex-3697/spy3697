"""Semi-automated assist for Broken Access Control / IDOR / BOLA / Missing
Authorization. There is no generic way to *detect* these automatically —
they're business-logic issues (does user A's token let them read user B's
record?) that require you to tell the tool what "should" be denied. This
module does not guess: you supply the URL pattern, the object IDs to try,
and the credentials/tokens for each role, and it captures the actual
responses side-by-side as evidence. A human (or the LLM, citing the specific
evidence_ids) then judges whether access was improperly allowed — the module
itself never asserts a verdict.
"""
from __future__ import annotations
from ..evidence import EvidenceStore
from .http_wrapper import http_request


def probe_object_ids(
    store: EvidenceStore, run_id: str, target: str, url_template: str,
    object_ids: list[str], role_headers: dict[str, dict] | None = None,
) -> list[dict]:
    """url_template should contain '{id}', e.g. 'https://host/api/orders/{id}'.
    role_headers: optional dict of role_name -> headers (e.g. an Authorization
    token) to send with each request, so you can compare "user A" vs "user B"
    vs "no auth" access to the same object. Returns a list of
    {object_id, role, evidence_id, status_code} for you/the LLM to review —
    it does not itself decide anything is a vulnerability.
    """
    role_headers = role_headers or {"no-auth": {}}
    results = []
    for oid in object_ids:
        url = url_template.format(id=oid)
        for role, headers in role_headers.items():
            eid, resp, _ = http_request(
                store, run_id, target, "GET", url, headers=headers,
                stage="verify", timeout=15,
            )
            results.append({
                "object_id": oid,
                "role": role,
                "evidence_id": eid,
                "status_code": resp.status_code if resp else None,
            })
    return results
