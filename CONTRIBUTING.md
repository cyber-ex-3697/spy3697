# Contributing to SPY-3697

Thanks for considering a contribution. A few ground rules to keep this
project safe and maintainable:

## Scope of contributions

- **Yes:** new tool wrappers for existing, well-known security tools
  (e.g. ffuf, wpscan, nikto), better LLM prompt design, additional report
  formats, web UI improvements, bug fixes, tests, docs.
- **No:** novel exploit payloads, weaponized code for undisclosed/unpatched
  vulnerabilities, anything that removes or weakens the authorization gate
  in `guardrails.py`, or anything that lets the LLM bypass the evidence-citation
  requirement in `evidence.py` / `report.py`. See `LEGAL_AND_ETHICAL_USE.md`.

## Getting started

```bash
git clone https://github.com/<your-username>/spy3697.git
cd spy3697
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml   # add your own LLM key + a lab target for testing
```

## Before opening a PR

1. Make sure `python -c "import spy3697.cli"` and the other modules still
   import cleanly (no missing deps, no circular imports).
2. If you touch `evidence.py`, `guardrails.py`, or `report.py`, add/update a
   test showing the safety property still holds (e.g. "a finding citing a
   nonexistent evidence_id is still rejected").
3. Run against a lab target (a local DVWA/VulnHub VM, or a CTF box you're
   authorized on) end-to-end if your change touches the orchestrator or a
   tool wrapper.
4. Keep tool wrappers thin: shell out to the real tool, capture output as
   evidence, don't reimplement scanning logic in Python.

## Reporting bugs / requesting features

Open a GitHub issue. For anything security-sensitive about SPY-3697 itself
(not findings it produces about a target), see `SECURITY.md`.
