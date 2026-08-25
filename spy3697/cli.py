from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from . import orchestrator as orc
from .config import load_config
from .guardrails import require_authorization, require_active_allowed, AuthorizationError
from .llm import build_llm
from .tools import packet_capture, shell_exec, dalfox_wrapper, trivy_wrapper, authz_matrix, ai_probe
from .evidence import EvidenceStore

app = typer.Typer(add_completion=False, help="SPY-3697 — authorized-use AI pentest orchestrator")
console = Console()

BANNER = Text.from_markup(
    "[bold orange3]SPY[/bold orange3][bold]\u20133697[/bold]  "
    "[dim]authorized-use AI pentest orchestrator[/dim]"
)

STAGE_COLORS = {
    "[recon]": "cyan", "[identify]": "yellow", "[verify]": "green",
    "[report]": "magenta", "[error]": "red", "[auth-error]": "red",
}


def _load(config_path: str):
    cfg = load_config(config_path)
    llm = build_llm(cfg.llm)
    return cfg, llm


def _echo(msg: str):
    style = next((s for prefix, s in STAGE_COLORS.items() if msg.startswith(prefix)), None)
    console.print(msg, style=style)


@app.command()
def run(
    target: str,
    goal: str = typer.Option("Check this target for common vulnerabilities", "--goal"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
    formats: str = typer.Option("md", "--formats", help="comma list: md,docx"),
):
    """One-click full pipeline: recon -> identify -> verify -> report + PoC."""
    console.print(BANNER)
    console.print(f"[dim]target=[/dim]{target}  [dim]goal=[/dim]{goal}\n")
    cfg, llm = _load(config)
    try:
        ctx = orc.run_full_pipeline(cfg, llm, target, goal, i_confirm_authorization, log=_echo)
    except AuthorizationError as e:
        console.print(Panel(str(e), title="[red]Authorization error[/red]", border_style="red"))
        raise typer.Exit(code=2)
    orc.stage_report(ctx, formats=formats.split(","))

    findings = ctx.store.list_findings(ctx.run_id)
    verified = [f for f in findings if f["status"] == "verified"]
    candidates = [f for f in findings if f["status"] == "candidate"]
    summary = Table(title=f"Run {ctx.run_id} \u2014 results", show_lines=False)
    summary.add_column("Status"); summary.add_column("Count")
    summary.add_row("[green]Verified findings[/green]", str(len(verified)))
    summary.add_row("[yellow]Unverified candidates[/yellow]", str(len(candidates)))
    console.print(summary)
    console.print(Panel(
        f"report: {ctx.workspace / 'report.md'}\nPoC scripts: {ctx.workspace / 'poc'}",
        title="[bold]Output[/bold]", border_style="green",
    ))


@app.command()
def recon(
    target: str,
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    cfg, llm = _load(config)
    try:
        ctx = orc.init_run(cfg, llm, target, "recon only", i_confirm_authorization, log=_echo)
        orc.stage_recon(ctx)
        console.print(f"[green]Run id:[/green] {ctx.run_id}")
    except AuthorizationError as e:
        console.print(f"[red]Authorization error:[/red] {e}")
        raise typer.Exit(code=2)


@app.command()
def scan(
    target: str,
    run_id: str = typer.Option(..., "--run-id"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    """Vulnerability identification against an existing run's recon evidence."""
    cfg, llm = _load(config)
    require_authorization(cfg, target, i_confirm_authorization)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    ctx = orc.RunContext(run_id=run_id, target=target, goal="scan", cfg=cfg, llm=llm,
                          store=store, workspace=workspace, log=_echo)
    candidates = orc.stage_identify(ctx)
    table = Table(title="Candidate findings")
    table.add_column("ID"); table.add_column("Severity"); table.add_column("Title")
    for c in candidates:
        table.add_row(str(c["finding_id"]), c.get("severity", ""), c["title"])
    console.print(table)


@app.command()
def verify(
    target: str,
    run_id: str = typer.Option(..., "--run-id"),
    finding_id: int = typer.Option(..., "--finding-id"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    cfg, llm = _load(config)
    require_authorization(cfg, target, i_confirm_authorization)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    ctx = orc.RunContext(run_id=run_id, target=target, goal="verify", cfg=cfg, llm=llm,
                          store=store, workspace=workspace, log=_echo)
    orc.stage_verify(ctx, finding_id)


@app.command()
def report(
    run_id: str = typer.Option(..., "--run-id"),
    target: str = typer.Option(..., "--target"),
    config: str = typer.Option("config.yaml", "--config"),
    formats: str = typer.Option("md", "--formats"),
):
    cfg, llm = _load(config)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    ctx = orc.RunContext(run_id=run_id, target=target, goal="report", cfg=cfg, llm=llm,
                          store=store, workspace=workspace, log=_echo)
    orc.stage_report(ctx, formats=formats.split(","))


@app.command()
def pcap(
    action: str = typer.Argument(..., help="'start' to capture"),
    target: str = typer.Option(..., "--target"),
    iface: str = typer.Option("eth0", "--iface"),
    bpf: str = typer.Option("", "--filter"),
    duration: int = typer.Option(30, "--duration"),
    run_id: Optional[str] = typer.Option(None, "--run-id"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    cfg, llm = _load(config)
    require_authorization(cfg, target, i_confirm_authorization)
    require_active_allowed(cfg, target)
    rid = run_id or orc.new_run_id()
    workspace = cfg.workspace_dir / target.replace("/", "_") / rid
    store = EvidenceStore(workspace / "evidence.sqlite")
    eid, pcap_path, summary = packet_capture.capture(
        store, cfg, rid, target, iface, bpf or f"host {target}", duration, workspace / "pcap"
    )
    console.print(f"[green]Capture saved:[/green] {pcap_path}\n{summary[:2000]}")


@app.command()
def exec(
    target: str,
    command: str,
    run_id: str = typer.Option(..., "--run-id"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    cfg, llm = _load(config)
    require_authorization(cfg, target, i_confirm_authorization)
    require_active_allowed(cfg, target)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    eid, output, code = shell_exec.run_command(store, cfg, run_id, target, command)
    console.print(f"[green]exit={code} evidence=#{eid}[/green]\n{output}")


@app.command()
def web(
    port: int = typer.Option(8765, "--port"),
    config: str = typer.Option("config.yaml", "--config"),
):
    import uvicorn
    from .webui.app import build_app
    uvicorn.run(build_app(config), host="127.0.0.1", port=port)


@app.command()
def xss(
    target: str,
    url: str = typer.Option(..., "--url"),
    run_id: str = typer.Option(..., "--run-id"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    """Standalone XSS scan via dalfox."""
    cfg, _llm = _load(config)
    require_authorization(cfg, target, i_confirm_authorization)
    require_active_allowed(cfg, target)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    eid, output = dalfox_wrapper.scan_url(store, cfg, run_id, url)
    console.print(f"[green]evidence #{eid}[/green]\n{output[:3000]}")


@app.command()
def sca(
    target: str,
    path: str = typer.Option(..., "--path", help="local filesystem path to scan for vulnerable deps"),
    run_id: str = typer.Option(..., "--run-id"),
    config: str = typer.Option("config.yaml", "--config"),
):
    """Supply-chain / dependency vulnerability scan via trivy. No network
    target needed -- scans a local path, so it doesn't go through the
    authorization gate the same way (nothing is sent over the network)."""
    cfg, _llm = _load(config)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    eid, output = trivy_wrapper.scan_filesystem(store, cfg, run_id, target, path)
    console.print(f"[green]evidence #{eid}[/green]\n{output[:3000]}")


@app.command()
def authz_check(
    target: str,
    url_template: str = typer.Option(..., "--url-template", help="e.g. https://host/api/orders/{id}"),
    ids: str = typer.Option(..., "--ids", help="comma-separated object ids to try, e.g. 1,2,3"),
    run_id: str = typer.Option(..., "--run-id"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    """BOLA/IDOR/missing-authorization assist: fetches url_template for each
    id, unauthenticated. For authenticated role comparisons, use the Python
    API (spy3697.tools.authz_matrix.probe_object_ids) directly with your
    role tokens -- the CLI here covers the simple no-auth-vs-object case."""
    cfg, _llm = _load(config)
    require_authorization(cfg, target, i_confirm_authorization)
    require_active_allowed(cfg, target)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    id_list = [i.strip() for i in ids.split(",")]
    results = authz_matrix.probe_object_ids(store, run_id, target, url_template, id_list)
    table = Table(title="Authorization matrix results")
    table.add_column("Object ID"); table.add_column("Role"); table.add_column("Status"); table.add_column("Evidence")
    for r in results:
        table.add_row(str(r["object_id"]), r["role"], str(r["status_code"]), f"#{r['evidence_id']}")
    console.print(table)
    console.print("[yellow]Review the responses above -- this tool captures evidence, it does not judge "
                  "whether access should have been denied.[/yellow]")


@app.command()
def ai_probe_cmd(
    target: str,
    url: str = typer.Option(..., "--url"),
    prompt_field: str = typer.Option("message", "--prompt-field"),
    run_id: str = typer.Option(..., "--run-id"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
):
    """Sends benign prompt-injection canary probes to an AI-backed API
    endpoint you're authorized to test."""
    cfg, _llm = _load(config)
    require_authorization(cfg, target, i_confirm_authorization)
    require_active_allowed(cfg, target)
    workspace = cfg.workspace_dir / target.replace("/", "_") / run_id
    store = EvidenceStore(workspace / "evidence.sqlite")
    results = ai_probe.probe_endpoint(store, run_id, target, url, prompt_field=prompt_field)
    table = Table(title="Prompt-injection probe results")
    table.add_column("Probe"); table.add_column("Status"); table.add_column("Evidence")
    for r in results:
        table.add_row(r["probe"][:50] + "...", str(r["status_code"]), f"#{r['evidence_id']}")
    console.print(table)


if __name__ == "__main__":
    app()
