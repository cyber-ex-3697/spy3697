# Legal and Ethical Use

SPY-3697 automates active reconnaissance, vulnerability scanning, and exploit
verification. Those actions are illegal in most jurisdictions when performed
against a system you don't own or don't have explicit written permission to
test (e.g. under the U.S. Computer Fraud and Abuse Act, UK Computer Misuse
Act, and equivalents elsewhere).

**Only run this against:**
- Infrastructure you own,
- CTF boxes / ranges designed for this purpose (HackTheBox, TryHackMe,
  PortSwigger Web Security Academy, PentesterLab, a local VulnHub/DVWA VM,
  etc.),
- Targets covered by a signed penetration-testing engagement / scope
  document you or your organization holds.

**Built-in safeguards, not a substitute for your judgment:**
- Active modules refuse to run unless the target matches `authorized_targets`
  in `config.yaml` or you pass an explicit authorization confirmation
  (`--i-confirm-authorization` / the web UI checkbox).
- `passive_only_targets` in config disables active scanning/exploitation/exec
  entirely for listed hosts.
- A command denylist blocks obviously destructive operations regardless of
  confirmation.

These guardrails only enforce *that you confirmed authorization* — they
cannot verify you actually have it. That responsibility is yours.

## Reporting a vulnerability found using this tool

If you discover a real-world vulnerability while legitimately testing a
system you're authorized to test, follow that organization's responsible
disclosure / bug bounty process. Do not use SPY-3697's findings or PoC
scripts against systems outside your authorized scope.

## Contributing exploit content

Pull requests that add novel exploit payloads, weaponized shellcode, or
techniques aimed at unpatched/undisclosed vulnerabilities will not be
accepted. This project integrates existing, purpose-built, publicly
maintained security tools (nmap, nuclei, sqlmap, etc.) — it is not a
vulnerability research or exploit-development project.
