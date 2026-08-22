from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import orchestrator as orc
from .config import load_config
from .guardrails import require_authorization, require_active_allowed, AuthorizationError
from .llm import build_llm
from .tools import packet_capture, shell_exec
from .evidence import EvidenceStore

app = typer.Typer(add_completion=False, help="SPY-3697 — authorized-use AI pentest orchestrator")
console = Console()


def _load(config_path: str):
    cfg = load_config(config_path)
    llm = build_llm(cfg.llm)
    return cfg, llm


def _echo(msg: str):
    console.print(msg)


@app.command()
def run(
    target: str,
    goal: str = typer.Option("Check this target for common vulnerabilities", "--goal"),
    config: str = typer.Option("config.yaml", "--config"),
    i_confirm_authorization: bool = typer.Option(False, "--i-confirm-authorization"),
    formats: str = typer.Option("md", "--formats", help="comma list: md,docx"),
):
    """One-click full pipeline: recon -> identify -> verify -> report + PoC."""
    cfg, llm = _load(config)
    try:
        ctx = orc.run_full_pipeline(cfg, llm, target, goal, i_confirm_authorization, log=_echo)
    except AuthorizationError as e:
        console.print(f"[red]Authorization error:[/red] {e}")
        raise typer.Exit(code=2)
    orc.stage_report(ctx, formats=formats.split(","))


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


if __name__ == "__main__":
    app()
