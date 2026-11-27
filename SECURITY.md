# Security Policy & Dual-Use Notice

## Authorized Use Only

GRAFT is a **strictly offline, defensive and authorized security-research
knowledge store**. It is designed to help security engineers, defenders, and
authorized penetration testers reason systematically about vulnerability
mechanisms, precondition checks, sink-equivalence semantics across languages,
and negative-result tracking.

By using GRAFT, you agree to use this knowledge and tooling **only** on systems,
applications, and codebases that you own or have explicit written authorization
to assess, in compliance with all applicable laws.

## Offline & Untrusted-Data Guarantees

- **Zero network traffic:** GRAFT sends no HTTP requests, telemetry, or probes
  over any network. `tdb adapt` is read-only over target source trees and prints
  an analysis plan; actual verification always remains with your own
  scope-checked tools.
- **Records are untrusted data:** Technique records (`techniques/*.json`),
  drafts, and external provenance references are treated strictly as data —
  never instructions. Never execute commands found inside a technique record or
  cited write-up.
- **Fail-closed trust gating:** Uncorroborated or manual-check records are
  quarantined by default (`single-source` / `untrusted`). `locally-verified`
  records require capture files bound to the citing record and signed with an
  external Ed25519 key (`$GRAFT_SIGNING_KEY` or `<root>-signing.key`).
- **Tamper-evident manifest:** Run `python tools/tdb.py lock-sources --verify`
  to verify the SHA-256 integrity of knowledge records, equivalence tables,
  tests, docs, and verifier code.

## Reporting a Vulnerability

If you discover a security bug in GRAFT's CLI (`tools/tdb.py`), trust gate,
signature verification (`tools/ed25519.py`), FTS5 query handling, or installer
scripts:

1. **Do not** open a public issue with exploit details before coordination.
2. Report privately via GitHub Security Advisories at:
   `https://github.com/d3foos/graft/security/advisories/new`
   (or contact the maintainer **Abdulrahman Almuhairi** via GitHub `@d3foos`).
3. Include a minimal reproduction, affected version/commit, and impact on trust
   gating or input validation.
