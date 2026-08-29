"""The recon -> identify -> verify -> report pipeline.

Design principle: the LLM proposes *which tool to run next* and *how to
interpret evidence*, but it never fabricates evidence itself. Every finding
that reaches "verified" status must be backed by an evidence_id produced by
an actual tool run in this file. The orchestrator is the thing that enforces
that — see `evidence.add_finding()`, which raises if evidence_ids don't exist.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .config import Config
from .evidence import EvidenceStore
from .guardrails import require_authorization, require_active_allowed, AuthorizationError
from .llm import LLMConnector
from .tools import nmap_wrapper, http_wrapper, nuclei_wrapper, sqlmap_wrapper, bruteforce_wrapper
from .tools import dalfox_wrapper, trivy_wrapper, nikto_wrapper
from .report import generate_report

Logger = Callable[[str], None]


@dataclass
class RunContext:
    run_id: str
    target: str
    goal: str
    cfg: Config
    llm: LLMConnector
    store: EvidenceStore
    workspace: Path
    log: Logger = field(default=lambda msg: print(msg))


def new_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def init_run(cfg: Config, llm: LLMConnector, target: str, goal: str,
             confirmed_by_user: bool, log: Logger = print) -> RunContext:
    require_authorization(cfg, target, confirmed_by_user)
    run_id = new_run_id()
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    workspace.mkdir(parents=True, exist_ok=True)
    store = EvidenceStore(workspace / "evidence.sqlite")
    log(f"[+] Run {run_id} initialized for target={target} at {workspace}")
    return RunContext(run_id=run_id, target=target, goal=goal, cfg=cfg, llm=llm,
                       store=store, workspace=workspace, log=log)


# ---------------------------------------------------------------------------
# Stage 1: Recon
# ---------------------------------------------------------------------------

def stage_recon(ctx: RunContext) -> None:
    require_active_allowed(ctx.cfg, ctx.target)
    ctx.log(f"[recon] port scanning {ctx.target} ...")
    eid, output = nmap_wrapper.port_scan(ctx.store, ctx.cfg, ctx.run_id, ctx.target)
    ctx.log(f"[recon] nmap done, evidence #{eid} ({len(output)} bytes)")

    ctx.log(f"[recon] probing HTTP(S) ...")
    for scheme, port in (("http", 80), ("https", 443)):
        url = f"{scheme}://{ctx.target}/"
        eid, resp, _ = http_wrapper.http_get(ctx.store, ctx.run_id, ctx.target, url)
        status = resp.status_code if resp else "no response"
        ctx.log(f"[recon] {url} -> {status} (evidence #{eid})")

    ctx.log("[recon] directory discovery on :80 ...")
    try:
        eid, output = bruteforce_wrapper.dir_scan(
            ctx.store, ctx.cfg, ctx.run_id, f"http://{ctx.target}/"
        )
        ctx.log(f"[recon] gobuster done, evidence #{eid}")
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[recon] gobuster skipped/failed: {e}")


# ---------------------------------------------------------------------------
# Stage 2: Identify (vulnerability candidates)
# ---------------------------------------------------------------------------

def stage_identify(ctx: RunContext) -> list[dict]:
    require_active_allowed(ctx.cfg, ctx.target)
    ctx.log("[identify] running nuclei template scan (cve,xss,ssrf,xxe,csrf,misconfig,"
            "rce,injection,lfi,deserialization,auth-bypass) ...")
    eid, nuclei_out = nuclei_wrapper.scan(ctx.store, ctx.cfg, ctx.run_id, f"http://{ctx.target}/")
    ctx.log(f"[identify] nuclei done, evidence #{eid}")

    ctx.log("[identify] running dalfox XSS scan ...")
    try:
        eid, dalfox_out = dalfox_wrapper.scan_url(ctx.store, ctx.cfg, ctx.run_id, f"http://{ctx.target}/")
        ctx.log(f"[identify] dalfox done, evidence #{eid}")
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[identify] dalfox skipped/failed: {e}")

    ctx.log("[identify] running nikto web vulnerability scan ...")
    try:
        eid, nikto_out = nikto_wrapper.scan(ctx.store, ctx.cfg, ctx.run_id, ctx.target)
        ctx.log(f"[identify] nikto done, evidence #{eid}")
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[identify] nikto skipped/failed: {e}")

    # Let the LLM read *all* recon+identify evidence collected so far and
    # propose candidate findings, each citing evidence_ids it actually saw.
    evidence_records = ctx.store.list_evidence(ctx.run_id)
    evidence_summary = _format_evidence_for_llm(evidence_records)

    prompt = f"""Goal: {ctx.goal}
Target: {ctx.target}

Below is every evidence record collected so far (id, tool, command, truncated output).
Propose a list of vulnerability CANDIDATES worth verifying. Do not claim anything is
confirmed yet — that happens in the verify stage. Every candidate must cite the
evidence_id(s) that suggested it. If you have no evidence-backed candidates, return
an empty list rather than inventing one.

Evidence:
{evidence_summary}

Respond with ONLY a JSON array like:
[{{"title": "...", "severity": "low|medium|high|critical", "description": "...",
   "evidence_ids": [1,2], "suggested_verification": "what tool/command would confirm this"}}]
"""
    try:
        candidates = ctx.llm.complete_json([{"role": "user", "content": prompt}])
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[identify] LLM proposal failed to parse: {e}")
        candidates = []

    stored = []
    for c in candidates:
        try:
            fid = ctx.store.add_finding(
                run_id=ctx.run_id, target=ctx.target, title=c["title"],
                severity=c.get("severity", "info"), status="candidate",
                evidence_ids=c.get("evidence_ids", []),
                description=c.get("description", ""),
            )
            c["finding_id"] = fid
            stored.append(c)
            ctx.log(f"[identify] candidate #{fid}: {c['title']} ({c.get('severity')})")
        except ValueError as e:
            # LLM cited evidence_ids that don't exist -> reject, don't silently keep it
            ctx.store.log_unverified_claim(ctx.run_id, json.dumps(c), str(e))
            ctx.log(f"[identify] REJECTED candidate (bad evidence refs): {c.get('title')}")
    return stored


def _format_evidence_for_llm(records) -> str:
    lines = []
    for r in records:
        snippet = r.raw_output[:800].replace("\n", " ")
        lines.append(f"[evidence:{r.id}] tool={r.tool} stage={r.stage} cmd={r.command}\n  {snippet}")
    return "\n".join(lines) if lines else "(none)"


# ---------------------------------------------------------------------------
# Stage 3: Verify
# ---------------------------------------------------------------------------

def stage_verify(ctx: RunContext, finding_id: int) -> None:
    require_active_allowed(ctx.cfg, ctx.target)
    findings = {f["id"]: f for f in ctx.store.list_findings(ctx.run_id)}
    finding = findings.get(finding_id)
    if not finding:
        ctx.log(f"[verify] finding #{finding_id} not found")
        return

    ctx.log(f"[verify] verifying finding #{finding_id}: {finding['title']}")

    # Ask the LLM to propose ONE concrete, safe verification step given the
    # evidence so far. It must choose from the known tool set — it cannot
    # invent arbitrary exploit code.
    cited = ctx.store.list_evidence(ctx.run_id)
    prompt = f"""Finding to verify: {json.dumps(finding)}
Target: {ctx.target}
Goal: {ctx.goal}

Available verification actions (pick exactly one):
- "sqlmap": {{"url": "...", "data": "optional post body"}}
- "http_request": {{"method": "GET|POST", "url": "...", "params": {{}}, "data": {{}}}}
- "nuclei_recheck": {{"url": "...", "tags": "optional nuclei tag filter"}}
- "none": nothing safe/available to verify further with current tooling

Respond with ONLY JSON: {{"action": "...", "args": {{...}}, "rationale": "..."}}
"""
    try:
        plan = ctx.llm.complete_json([{"role": "user", "content": prompt}])
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[verify] LLM verification plan failed to parse: {e}")
        return

    action = plan.get("action")
    args = plan.get("args", {})
    ctx.log(f"[verify] plan: {action} {args} -- {plan.get('rationale','')}")

    new_evidence_id = None
    poc_command = None

    if action == "sqlmap":
        eid, output = sqlmap_wrapper.test_url(
            ctx.store, ctx.cfg, ctx.run_id, args["url"], data=args.get("data")
        )
        new_evidence_id = eid
        confirmed = "vulnerable" in output.lower() or "parameter" in output.lower() and "injectable" in output.lower()
        poc_command = f"sqlmap -u {args['url']!r} --batch" + (f" --data {args.get('data')!r}" if args.get("data") else "")
    elif action == "http_request":
        eid, resp, output = http_wrapper.http_request(
            ctx.store, ctx.run_id, ctx.target, args.get("method", "GET"), args["url"],
            params=args.get("params"), data=args.get("data"),
        )
        new_evidence_id = eid
        confirmed = resp is not None and resp.status_code < 500
        m = (args.get("method", "GET"))
        poc_command = f"curl -sk -X {m} {args['url']!r}"
    elif action == "nuclei_recheck":
        eid, output = nuclei_wrapper.scan(
            ctx.store, ctx.cfg, ctx.run_id, args["url"], tags=args.get("tags")
        )
        new_evidence_id = eid
        confirmed = bool(output.strip())
        poc_command = f"nuclei -u {args['url']!r}" + (f" -tags {args.get('tags')!r}" if args.get("tags") else "")
    else:
        ctx.log("[verify] no further verification action taken")
        return

    # Re-ask the LLM to judge confirm/reject, but ONLY grounded in the new
    # evidence record's actual content, and require it to cite it.
    ev = ctx.store.get_evidence(new_evidence_id)
    judge_prompt = f"""Verification was attempted. Here is the exact evidence captured:

[evidence:{ev.id}] tool={ev.tool} command={ev.command}
output:
{ev.raw_output[:3000]}

Question: does this evidence CONFIRM the finding "{finding['title']}"? Answer with ONLY
JSON: {{"verified": true|false, "reasoning": "must reference evidence:{ev.id} specifically"}}
"""
    try:
        verdict = ctx.llm.complete_json([{"role": "user", "content": judge_prompt}])
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[verify] LLM verdict failed to parse: {e}")
        return

    if verdict.get("verified") and f"evidence:{ev.id}" in verdict.get("reasoning", ""):
        # DOUBLE-CHECK: re-ask independently, differently worded, before
        # trusting the first verdict. Both passes must agree that this
        # specific evidence confirms the finding, or we back off to
        # "candidate" instead of asserting VERIFIED on a single pass.
        second_prompt = f"""Independently re-examine this evidence. Do not assume the
finding is correct -- look only at what the evidence actually shows.

[evidence:{ev.id}] tool={ev.tool} command={ev.command}
output:
{ev.raw_output[:3000]}

Claim under review: "{finding['title']}"

Does the evidence above, on its own, actually demonstrate this claim is true? Answer
with ONLY JSON: {{"agrees": true|false, "reasoning": "must reference evidence:{ev.id}"}}
"""
        second_agrees = False
        try:
            second_verdict = ctx.llm.complete_json([{"role": "user", "content": second_prompt}])
            second_agrees = bool(second_verdict.get("agrees")) and f"evidence:{ev.id}" in second_verdict.get("reasoning", "")
        except Exception as e:  # noqa: BLE001
            ctx.log(f"[verify] double-check pass failed to parse: {e} -- treating as non-agreement")

        new_evidence_ids = json.loads(json.dumps(finding["evidence_ids"])) + [ev.id]
        ctx.store.conn.execute(
            "UPDATE findings SET evidence_ids=? WHERE id=?",
            (json.dumps(new_evidence_ids), finding_id),
        )
        ctx.store.conn.commit()

        if second_agrees:
            ctx.store.update_finding_status(finding_id, "verified", poc_command=poc_command)
            confidence = compute_confidence(ctx.store, finding_id, double_check_agreed=True)
            ctx.store.set_finding_confidence(finding_id, confidence)
            ctx.log(f"[verify] finding #{finding_id} VERIFIED (evidence #{ev.id}, "
                     f"double-check agreed, confidence {confidence}%)")
        else:
            # First pass said yes, second independent pass didn't agree --
            # don't assert this as confirmed. Leave as a candidate with a
            # lower confidence score and note the disagreement for review.
            ctx.store.update_finding_status(finding_id, "candidate", poc_command=poc_command)
            confidence = compute_confidence(ctx.store, finding_id, double_check_agreed=False)
            ctx.store.set_finding_confidence(finding_id, confidence)
            ctx.store.log_unverified_claim(
                ctx.run_id, f"finding #{finding_id} verification claim",
                f"initial verify said yes but double-check disagreed: {second_verdict.get('reasoning', 'n/a') if 'second_verdict' in dir() else 'parse failure'}",
            )
            ctx.log(f"[verify] finding #{finding_id} NOT confidently verified "
                     f"(double-check disagreed, confidence {confidence}%) -- left as candidate")
    else:
        ctx.store.update_finding_status(finding_id, "rejected")
        ctx.store.set_finding_confidence(finding_id, 0)
        ctx.store.log_unverified_claim(
            ctx.run_id, f"finding #{finding_id} verification claim",
            verdict.get("reasoning", "did not cite evidence_id or verified=false"),
        )
        ctx.log(f"[verify] finding #{finding_id} NOT verified")


def compute_confidence(store: EvidenceStore, finding_id: int, double_check_agreed: bool) -> int:
    """Confidence score (0-100) computed from concrete signals, not guessed:
    - how much evidence backs the finding (more independent evidence = higher)
    - whether the source tool itself flagged the result as verified
      (e.g. nuclei's own 'verified':true matcher metadata)
    - whether an independent double-check pass agreed with the first verdict
    - whether a concrete PoC reproduction command was captured
    """
    row = store.conn.execute(
        "SELECT evidence_ids, poc_command FROM findings WHERE id=?", (finding_id,)
    ).fetchone()
    if not row:
        return 0
    evidence_ids = json.loads(row[0])
    poc_command = row[1]

    score = 0
    score += min(len(evidence_ids) * 12, 36)  # up to 36 for evidence breadth

    tool_verified_flag = False
    for eid in evidence_ids:
        ev = store.get_evidence(eid)
        if ev and '"verified":true' in ev.raw_output.replace(" ", ""):
            tool_verified_flag = True
            break
    if tool_verified_flag:
        score += 24  # the underlying tool itself marked this as a confirmed match

    if double_check_agreed:
        score += 30  # independent second pass agreed
    else:
        score += 5   # some signal existed, but not corroborated independently

    if poc_command:
        score += 10  # a concrete, runnable reproduction was captured

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Stage 4: Report
# ---------------------------------------------------------------------------

def stage_report(ctx: RunContext, formats: list[str]) -> list[Path]:
    ctx.log("[report] generating report + PoC scripts ...")
    paths = generate_report(ctx.store, ctx.run_id, ctx.target, ctx.workspace, formats, ctx.llm)
    for p in paths:
        ctx.log(f"[report] wrote {p}")
    return paths


# ---------------------------------------------------------------------------
# One-click full pipeline
# ---------------------------------------------------------------------------

def run_full_pipeline(cfg: Config, llm: LLMConnector, target: str, goal: str,
                       confirmed_by_user: bool, log: Logger = print) -> RunContext:
    ctx = init_run(cfg, llm, target, goal, confirmed_by_user, log=log)
    stage_recon(ctx)
    candidates = stage_identify(ctx)
    for c in candidates:
        try:
            stage_verify(ctx, c["finding_id"])
        except AuthorizationError as e:
            ctx.log(f"[verify] blocked: {e}")
            break
    stage_report(ctx, formats=["md"])
    ctx.log(f"[+] Run {ctx.run_id} complete. Workspace: {ctx.workspace}")
    return ctx
