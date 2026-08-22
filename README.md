# SPY-3697

![CI](https://github.com/YOUR_USERNAME/spy3697/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)

An LLM-orchestrated penetration testing assistant for **authorized** CTFs, target ranges, and
scoped engagements. See [`LEGAL_AND_ETHICAL_USE.md`](LEGAL_AND_ETHICAL_USE.md) before running
this against anything. It chains recon → vulnerability identification → verification → report/PoC
generation, driven by plain-language instructions, while keeping every conclusion tied to
captured tool output rather than model guesswork.

> ⚠️ **Authorization required.** SPY-3697 will refuse to run any active module (port scans,
> web fuzzing, sqlmap, exploit verification, packet capture, arbitrary command execution)
> against a target that is not listed in `authorized_targets` in your config, or passed with
> `--i-confirm-authorization`. This is a hard gate, not a suggestion — see `spy3697/config.py`
> and `spy3697/guardrails.py`. You are responsible for only pointing this at systems you own
> or have written permission to test (CTF boxes, HackTheBox/TryHackMe/PortSwigger-style ranges,
> your own lab, or a signed engagement scope).

## What it actually does

SPY-3697 is **not** a novel exploit generator. It's an orchestration layer:

- It shells out to well-known, purpose-built security tools (nmap, whatweb/httpx, nuclei,
  sqlmap, gobuster/ffuf, tcpdump/tshark) that already exist for authorized testing.
- An LLM (Claude, OpenAI-compatible, or a local Ollama model — your choice) reads the
  **actual output** of those tools and decides what to run next, what looks worth verifying,
  and how to phrase the report.
- Every claim in the final report is required to cite an `evidence_id` from the SQLite
  evidence log. If the LLM's proposed conclusion or "flag" can't be traced to a stored
  tool-output record, the orchestrator rejects it and asks the model to re-verify or drop it.
  The system does not accept free-text claims of a flag/credential/RCE as fact.
- "PoC generation" means: capture the exact request/command sequence that reproduced the
  finding during verification (e.g. the literal `curl` command, the sqlmap invocation and its
  matched payload, the nuclei template ID + match), and save that as a runnable shell script —
  not synthesized shellcode or a memory-corruption exploit.

## Install

```bash
git clone <this-repo> spy3697 && cd spy3697
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# External tools SPY-3697 shells out to (install what you need):
#   nmap, nuclei, sqlmap, gobuster or ffuf, whatweb or httpx, tshark/tcpdump
# Debian/Ubuntu example:
sudo apt install nmap sqlmap gobuster tshark whatweb
# nuclei / httpx (Go tools):
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

cp config.example.yaml config.yaml
# edit config.yaml: add your LLM API key(s) and your authorized_targets list
```

## One-click full run

```bash
spy3697 run 10.10.10.5 --i-confirm-authorization --goal "Check this target for common web vulnerabilities"
```

This runs recon → vuln ID → verification → report + PoC scripts, writing everything to
`./workspace/<target>/<run_id>/`.

## Individual stages

```bash
spy3697 recon 10.10.10.5 --i-confirm-authorization
spy3697 scan 10.10.10.5 --run-id <id>              # vuln identification against prior recon
spy3697 verify 10.10.10.5 --run-id <id> --finding-id <fid>
spy3697 report --run-id <id> --format md,docx
spy3697 pcap start --iface eth0 --filter "host 10.10.10.5"
spy3697 exec 10.10.10.5 --run-id <id> "curl -sk https://10.10.10.5/robots.txt"
```

## Local web UI

```bash
spy3697 web --port 8765
```

Open http://127.0.0.1:8765 — enter a target + goal, confirm authorization in the UI, and watch
recon/scan/verify/report stream live with every evidence record inline.

## LLM backends

Configured in `config.yaml`:

```yaml
llm:
  provider: anthropic        # anthropic | openai_compatible | ollama
  model: claude-sonnet-5
  api_key_env: ANTHROPIC_API_KEY
```

Swap `provider` to `openai_compatible` for OpenAI, Azure OpenAI, or any compatible endpoint
(set `base_url`), or `ollama` for a fully local model. See `spy3697/llm.py`.

## Evidence & no-guessing design

Every tool invocation, HTTP response, packet capture summary, and command output is written to
`workspace/<target>/<run_id>/evidence.sqlite` with a hash, timestamp, and raw output. The LLM is
only ever shown evidence records (with IDs) and is instructed — and structurally forced via the
report validator in `report.py` — to cite an `evidence_id` for every factual claim, finding,
severity rating, or flag value. Unsupported claims are stripped before the report is rendered
and logged as `unverified_llm_claim` for your review instead of being silently dropped.

## Project layout

```
spy3697/
  cli.py                 # typer CLI: run/recon/scan/verify/report/pcap/exec/web
  guardrails.py           # authorization gate, scope checks, dangerous-command denylist
  config.py               # config.yaml loader
  llm.py                  # Anthropic / OpenAI-compatible / Ollama connector
  evidence.py              # SQLite evidence store
  orchestrator.py          # the recon->id->verify->report pipeline + LLM planning loop
  report.py                # evidence-grounded report + PoC script generation
  tools/
    nmap_wrapper.py
    http_wrapper.py         # requests-based web probing, header/cert capture
    nuclei_wrapper.py
    sqlmap_wrapper.py
    bruteforce_wrapper.py   # gobuster/ffuf
    packet_capture.py       # tshark/tcpdump wrapper, writes .pcap + summary
    shell_exec.py           # sandboxed command execution with guardrails
  webui/
    app.py                  # FastAPI app, websocket log streaming
    templates/index.html
    static/app.js
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports/feature requests use the GitHub issue
templates; security issues in the tool itself go through [`SECURITY.md`](SECURITY.md) instead
of a public issue.

## License

[MIT](LICENSE) — plus the usage expectations in [`LEGAL_AND_ETHICAL_USE.md`](LEGAL_AND_ETHICAL_USE.md).
