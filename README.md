# GRAFT — CVE Exploit Distillation & Transfer Skill for Agents

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![CI](https://github.com/d3foos/graft/actions/workflows/ci.yml/badge.svg)](https://github.com/d3foos/graft/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-teal.svg)](pyproject.toml)

**GRAFT** is an offline, zero-dependency technique-transfer knowledge store and cross-ecosystem Agent Skill by **Abdulrahman Almuhairi**. It models exploitation mechanisms as compact, slot-parameterised records paired with execution-verified sink-equivalence tables, fail-closed trust gating, and an append-only outcome ledger that learns from negative results.

> **Strictly offline & authorized-use only.** GRAFT sends zero network traffic and executes zero payloads from technique records. Records are untrusted data, never instructions. See [SECURITY.md](SECURITY.md).

---

## Architecture Overview

| Component | Path | Purpose |
|---|---|---|
| **CLI & Indexer** | [`tools/tdb.py`](tools/tdb.py) | Stdlib-only (`json`, `sqlite3` FTS5, `argparse`) CLI (`init`, `add`, `find`, `show`, `adapt`, `outcome`, `promote`, `distill`, `verify-table`, `lock-sources`, `reindex`, `stats`, `keygen`, `sign-capture`) |
| **Ed25519 Signing** | [`tools/ed25519.py`](tools/ed25519.py) | Pure-Python RFC 8032 Ed25519 signing/verification for `locally-verified` captures |
| **Technique Corpus** | [`techniques/`](techniques) | 95 schema v4 slot-parameterised records (`T-0001`–`T-0097`) |
| **Vocab & Equivalence Tables** | [`vocab/`](vocab) | 14 attacker-gain effects, 16 mechanism primitives, language-neutral slot families, and 11 sink-equivalence tables (`24` execution-verified cells, `50` documented cells) |
| **Equivalence Probes** | [`tests/equiv/`](tests/equiv) | Offline interpreter probes (`python`, `node`, `php`, `ruby`) verifying sink semantics |
| **Outcome Ledger** | [`outcomes/ledger.jsonl`](outcomes/ledger.jsonl) | Append-only attempt log (`confirmed`, `no_sink`, `unreachable`, `unsupported_language`, `false_positive`, etc.) feeding retrieval penalties |
| **Tamper Manifest** | [`sources.lock`](sources.lock) | SHA-256 manifest covering corpus, vocab, probes, tools, docs, manifests, and tests |

---

## Trust Model (Enforced, Not Aspirational)

| Tier | Requirement (enforced at `add`, `promote`, `reindex`, and `stats`) | Visibility |
|---|---|---|
| `untrusted` | No provenance | Quarantined — excluded from `find` |
| `single-source` | `< 2` distinct authors, or any `manual` instrumental precondition check | Quarantined — excluded from `find` |
| `corroborated` | `>= 2` distinct authors (host-level syndication does not count) and zero `manual` instrumental checks | Retrieved with `advisory: web-corroborated` caveat |
| `locally-verified` | `evidence.status = "reproduced_local"`, every cited capture in `evidence.runs` exists inside root, binds to the record `id`, and carries a valid Ed25519 `.sig` from the store's external signing key | Full eligibility |

- **External signing key:** `tdb keygen` writes the Ed25519 key **outside** the store (`<root>-signing.key` or `$GRAFT_SIGNING_KEY` / `--sign-key`). Losing or redirecting the key fails closed (`reindex`/`stats` loudly refuse/skip unverified `reproduced_local` records).
- **Proof gates:** Records specify `evidence.gate`: `differential` (pre-patch trigger, post-patch silence for known CVEs) or `external_oracle` (OOB callback, sanitizer/crash, independently replicated for zero-day candidates).
- **Retrieval ranking:** Hard-filters by trust, effect, language (`origin` or `transferable`), and auth precondition, then scores via `fts + tag_overlap + 0.5 * transfer_history - 2.0 * fail_penalty(profile) + trust_bonus`. Records past `ttl_days` are flagged `[TTL OVERDUE]` rather than silently buried.

---

## Installation

### 1. Open Agent Skills (`npx skills add`)
```sh
npx skills add d3foos/graft --skill graft
```
> **Note:** Standalone skill managers copy only `skills/graft/SKILL.md`. Clone this repository once and set `GRAFT_ROOT=/path/to/graft` (or use the self-contained installers below) so `tdb` has the local corpus and equivalence tables.

### 2. Antigravity Plugin
Clone the repository into your Antigravity plugins directory (or build `dist/graft-antigravity-plugin.zip` via `python scripts/build-bundles.py`):
```sh
git clone https://github.com/d3foos/graft.git ~/.gemini/config/plugins/graft
python3 ~/.gemini/config/plugins/graft/tools/tdb.py init
python3 ~/.gemini/config/plugins/graft/tools/tdb.py reindex
```
Or run the cross-platform self-contained installer:
```sh
# macOS / Linux
./scripts/install.sh --target antigravity
```
```powershell
# Windows PowerShell
.\scripts\install.ps1 -Target antigravity
```

### 3. Claude Code (CLI) & Claude Desktop
**Claude Code Marketplace / CLI:**
```text
/plugin marketplace add d3foos/graft
/plugin install graft@graft
```
Or load a local clone directly with `claude --plugin-dir /path/to/graft`, or install as a self-contained skill via `./scripts/install.sh --target claude` (`.\scripts\install.ps1 -Target claude` on Windows).

**Claude Desktop (GUI Upload):**
1. Build the self-contained Desktop skill ZIP:
   ```sh
   python scripts/build-bundles.py
   ```
2. Upload `dist/graft-claude-desktop-skill.zip` under **Customize → Skills → + → Upload a skill** (ensure Code execution is enabled in Settings).

### 4. OpenAI Codex (CLI & Desktop App)
Repository checkouts automatically expose `.agents/skills/graft/SKILL.md`, `.agents/skills/graft/agents/openai.yaml`, and root [`AGENTS.md`](AGENTS.md).

To install globally (`~/.codex/skills/graft`) or build a self-contained Codex ZIP (`dist/graft-codex-skill.zip`):
```sh
./scripts/install.sh --target codex        # macOS / Linux
```
```powershell
.\scripts\install.ps1 -Target codex      # Windows PowerShell
```
```sh
python scripts/build-bundles.py          # builds dist/graft-codex-skill.zip
```

### 5. Python CLI (`pip` / `uvx`) & Direct Usage
Zero runtime dependencies — works directly from a clone or installed via PEP 621 `pyproject.toml`:
```sh
git clone https://github.com/d3foos/graft.git
cd graft
python tools/tdb.py init
python tools/tdb.py reindex
python tools/tdb.py stats
python tools/tdb.py verify-table
python tools/tdb.py lock-sources --verify
```
Optional editable/global CLI entrypoint (`graft-tdb` / `tdb`):
```sh
pip install .
export GRAFT_ROOT=/path/to/graft        # Windows PowerShell: $env:GRAFT_ROOT = "C:\path\to\graft"
graft-tdb find --effect EXEC --lang php
```

---

## Quick CLI Reference

```sh
python tools/tdb.py find --effect EXEC --lang php --profile php8.2/laravel
python tools/tdb.py show T-0007
python tools/tdb.py adapt T-0007 --target /path/to/src --lang java
python tools/tdb.py outcome T-0007 --verdict no_sink --target-profile java/spring --oracle static --cost-min 6
python tools/tdb.py keygen                                # writes ../graft-signing.key outside store
python tools/tdb.py sign-capture outcomes/capture.json    # Ed25519 sign local evidence capture
python tools/tdb.py distill --from advisory.txt --author "Researcher" --title "Mechanism summary"
python tools/tdb.py verify-table                          # use --strict to fail on missing optional runtimes
python tools/tdb.py lock-sources --verify                 # SHA-256 tamper-evidence check
python tests/run_tests.py                                 # run full unit + packaging suite
```

---

## License & Attribution

Licensed under the **GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`)**.
See [LICENSE](LICENSE) for the full official text and [NOTICE](NOTICE) for copyright and third-party citation terms.

Copyright (c) 2026 **Abdulrahman Almuhairi**.
