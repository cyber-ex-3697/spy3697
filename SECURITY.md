# Security Policy

This policy covers vulnerabilities **in SPY-3697 itself** (e.g. the
authorization gate can be bypassed, the evidence-citation check can be
tricked, command injection in a tool wrapper, credentials leaking into logs).

It does **not** cover vulnerabilities SPY-3697 discovers in a target you
scan — report those through that target's own responsible disclosure
process, not here.

## Reporting

Please do not open a public issue for security bugs in the tool. Instead,
use GitHub's private vulnerability reporting (Security tab → "Report a
vulnerability") on this repo, or email the maintainer listed in the repo
profile. Include:

- The version/commit you tested
- Steps to reproduce
- What you'd expect the guardrail to do vs. what it actually did

## Supported versions

Only the latest commit on `main` is supported. There are no released
version branches yet.
