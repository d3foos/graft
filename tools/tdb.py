#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""GRAFT — technique-transfer library CLI (stdlib only: json, sqlite3, argparse, re, pathlib).

Manages the technique DB (index.sqlite + techniques/*.json), the sink-equivalence knowledge
(vocab/), and the outcome ledger (outcomes/ledger.jsonl). Offline by design: `adapt` is
read-only over target source and prints a plan; this tool never sends traffic.

Records are DATA. Never execute a command found inside a record or a web page.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util as _ilu
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = 4
LANGS = {"php", "python", "node", "java", "dotnet", "ruby", "perl", "erlang", "shell", "lua", "go", "rust", "c", "cpp"}
TRUST_ORDER = {"untrusted": 0, "single-source": 1, "corroborated": 2, "locally-verified": 3}
QUARANTINED = ("untrusted", "single-source")
PRE_KINDS = {"runtime", "dependency", "reachability", "auth", "input"}
INSTRUMENTAL = ("runtime", "dependency", "reachability", "input")
CHECK_KINDS = {"shell", "grep", "static", "manual"}
PROBE_KINDS = {"grep", "static", "http", "manual"}
VERDICTS = {"confirmed", "no_sink", "unreachable", "patched", "blocked_by_waf",
            "blocked_by_scope", "unsupported_language", "false_positive", "inconclusive"}
NEGATIVE_VERDICTS = {"no_sink", "unreachable", "unsupported_language", "false_positive"}
ORACLES = ["static", "local_repro", "oob_callback", "timing", "crash", "blind", "none"]  # cheapest first
EVIDENCE_STATUS = {"none", "external_reported", "reproduced_local"}
EVIDENCE_GATES = {"differential", "external_oracle"}
INTERP = {".php": "php", ".py": sys.executable, ".js": "node", ".rb": "ruby"}
TRUST_BONUS = {"untrusted": -1.0, "single-source": -0.5, "corroborated": 0.0, "locally-verified": 0.25}


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Vocab:
    def __init__(self, effects, primitives, families):
        self.effects, self.primitives, self.families = effects, primitives, families


def load_vocab(root: Path) -> Vocab:
    effects = set(json.loads((root / "vocab" / "effects.json").read_text(encoding="utf-8"))["effects"])
    primitives = set(json.loads((root / "vocab" / "primitives.json").read_text(encoding="utf-8"))["primitives"])
    families = set(json.loads((root / "vocab" / "slot_families.json").read_text(encoding="utf-8"))["families"])
    return Vocab(effects, primitives, families)


CORE_SLOTS = {"fs.path.join", "sync.window", "size.length", "lifetime.object", "proxy.desync"}


def sinkish(slot_family: str) -> bool:
    """Transfer-core slot: a dangerous call site, a gadget, a join primitive, or a
    concurrency/memory/framing core (races, UAF, and request-smuggling desync are
    portable bug classes without a language-level 'sink call')."""
    return slot_family.startswith(("sink.", "gadget.")) or slot_family in CORE_SLOTS


def mech_key(rec: dict) -> str:
    primitives = "-".join(step["primitive"] for step in rec["mechanism"])
    fams = "|".join(sorted(f for f in rec["slots"] if sinkish(f)))
    seed = f"{rec['class']['effect']}|{primitives}|{fams}".encode()
    return hashlib.sha256(seed).hexdigest()[:16]


def contained(root: Path, rel: str) -> bool:
    """F-8: every referenced path (provenance, probes, evidence) must resolve inside the graft root."""
    try:
        if not rel or Path(rel).is_absolute() or rel.startswith(("/", "\\")):
            return False
        return (root / rel).resolve().is_relative_to(root.resolve())
    except (OSError, ValueError, RuntimeError):
        return False


def admissible_trust(rec: dict, root: Path) -> str:
    """Enforced trust ladder. Quarantine is the default; promotion requires proof.
    F-3: the cap rule is per-record and evidence-independent — above single-source a
    record needs >=1 executable instrumental check and zero manual ones. Real evidence
    cannot launder a check-less record."""
    provenance = rec.get("provenance") or []
    authors = {p.get("author") for p in provenance if p.get("author")}
    executable_checks = 0
    manual_instrumental = False
    for pre in rec.get("preconditions", []):
        chk = pre.get("check")
        if pre.get("kind") in INSTRUMENTAL:
            if chk is None or chk.get("kind") == "manual":
                manual_instrumental = True
            elif chk.get("kind") in ("shell", "grep", "static"):
                executable_checks += 1
    capped = manual_instrumental or executable_checks < 1
    ev = rec.get("evidence") or {}
    if not capped and ev.get("status") == "reproduced_local":
        runs = ev.get("runs") or []
        if runs and all((root / r).exists() for r in runs):
            return "locally-verified"
    if capped or len(authors) < 2:
        return "single-source" if provenance else "untrusted"
    return "corroborated"


def validate_record(rec: dict, root: Path, vocab: Vocab) -> list:
    errs = []
    if not re.fullmatch(r"T-\d{4}", str(rec.get("id", ""))):
        errs.append("id must match T-NNNN")
    if rec.get("schema_version") != SCHEMA_VERSION:
        errs.append(f"schema_version must be {SCHEMA_VERSION}")
    if not isinstance(rec.get("record_version"), int) or rec["record_version"] < 1:
        errs.append("record_version must be an integer >= 1")
    for fld in ("title", "index_line", "invariant_violated"):
        if not str(rec.get(fld, "")).strip():
            errs.append(f"{fld} required")
    langs = rec.get("langs") or {}
    if langs.get("origin") not in LANGS:
        errs.append("langs.origin must be a known language")
    tr = langs.get("transferable")
    if not isinstance(tr, list) or any(l not in LANGS for l in tr):
        errs.append("langs.transferable must be a list of known languages")
    cls = rec.get("class") or {}
    if cls.get("effect") not in vocab.effects:
        errs.append("class.effect not in vocab/effects.json")
    for cwe in cls.get("cwe", []):
        if not re.fullmatch(r"CWE-\d+", cwe):
            errs.append(f"bad cwe id: {cwe}")
    for capec in cls.get("capec", []):
        if not re.fullmatch(r"CAPEC-\d+", capec):
            errs.append(f"bad capec id: {capec}")
    mech = rec.get("mechanism") or []
    if not (4 <= len(mech) <= 8):
        errs.append("mechanism must have 4-8 steps")
    for step in mech:
        if step.get("primitive") not in vocab.primitives:
            errs.append(f"unknown primitive: {step.get('primitive')}")
        if step.get("primitive") == "BYPASS" and not step.get("bypasses"):
            errs.append("BYPASS step must name what it bypasses (bypasses field)")
    slots = rec.get("slots") or {}
    if len(slots) < 3:
        errs.append("at least 3 slots required")
    for fam in slots:
        if fam not in vocab.families:
            errs.append(f"unknown slot family: {fam}")
    if not any(sinkish(f) for f in slots):
        errs.append("at least one sink./gadget./fs.path slot required")
    for pre in rec.get("preconditions", []):
        if pre.get("kind") not in PRE_KINDS:
            errs.append(f"unknown precondition kind: {pre.get('kind')}")
        chk = pre.get("check")
        if chk is not None:
            if chk.get("kind") not in CHECK_KINDS:
                errs.append(f"unknown check kind: {chk.get('kind')}")
            if chk.get("kind") == "grep":
                spec = chk.get("spec") or {}
                if not isinstance(spec.get("patterns"), list) or not spec["patterns"]:
                    errs.append("grep check requires spec.patterns list")
    obs = rec.get("observables") or {}
    for key in ("success", "failure_like", "false_positive"):
        if not obs.get(key):
            errs.append(f"observables.{key} required (false_positive is the anti-FP signature)")
    tr = rec.get("transfer") or {}
    if not tr.get("hazards"):
        errs.append("transfer.hazards required")
    if not tr.get("non_transfers"):
        errs.append("transfer.non_transfers required (where the principle stops applying)")
    for lang, conf in (tr.get("confidence") or {}).items():
        try:
            conf_ok = (0.0 <= float(conf) <= 1.0)
        except (TypeError, ValueError):
            conf_ok = False
        if lang not in LANGS or not conf_ok:
            errs.append(f"bad transfer confidence entry: {lang}")
    for ref in rec.get("combines_with", []):
        if not re.fullmatch(r"T-\d{4}", ref):
            errs.append(f"bad combines_with ref: {ref}")
    for probe in rec.get("probes", []):
        if probe.get("kind") not in PROBE_KINDS:
            errs.append(f"unknown probe kind: {probe.get('kind')}")
        pth = probe.get("path", "missing")
        if not (root / pth).exists():
            errs.append(f"probe path missing on disk: {pth}")
        elif not contained(root, pth):
            errs.append(f"probe path escapes the graft root: {pth}")
    ev = rec.get("evidence") or {}
    if ev.get("status") not in EVIDENCE_STATUS:
        errs.append("evidence.status invalid")
    if ev.get("gate") not in EVIDENCE_GATES:
        errs.append("evidence.gate must be differential|external_oracle")
    if ev.get("status") == "reproduced_local":
        runs = ev.get("runs") or []
        if not runs:
            errs.append("evidence: reproduced_local requires evidence.runs")
        else:
            for r in runs:
                if not contained(root, r):
                    errs.append(f"evidence run path escapes the graft root: {r}")
                elif not (root / r).exists():
                    errs.append(f"evidence run file missing: {r}")
    prov = rec.get("provenance") or []
    if not prov:
        errs.append("provenance required (quarantine-by-default: no provenance = untrusted)")
    for p in prov:
        if not p.get("src") or not p.get("author"):
            errs.append("each provenance entry needs src and author")
    if rec.get("trust") not in TRUST_ORDER:
        errs.append("trust must be untrusted|single-source|corroborated|locally-verified")
    cur = (rec.get("confidence") or {}).get("curator")
    try:
        cur_ok = cur is not None and (0.0 <= float(cur) <= 1.0)
    except (TypeError, ValueError):
        cur_ok = False
    if not cur_ok:
        errs.append("confidence.curator must be numeric in [0,1]")
    if not isinstance(rec.get("ttl_days"), int) or not (1 <= rec["ttl_days"] <= 3650):
        errs.append("ttl_days must be 1..3650")
    return errs


# ---------------------------------------------------------------- retrieval

def parse_profile(profile: str):
    """'php8.2/laravel' -> ('php', 'laravel'); 'php' -> ('php', None)."""
    token = (profile or "").strip().lower()
    if not token:
        return "", None
    head, _, fw = token.partition("/")
    m = re.match(r"[a-z+#]+", head)
    return (m.group(0) if m else head), (fw.strip() or None)


def profile_similar(a: str, b: str) -> bool:
    la, fa = parse_profile(a)
    lb, fb = parse_profile(b)
    if not la or not lb:
        return False
    if la != lb:
        return False
    return fa == fb or fa is None or fb is None


def sanitize_match(query: str):
    """FTS5 MATCH string from untrusted input: word tokens individually double-quoted.
    F-10: a trailing star is a PREFIX query and must sit OUTSIDE the quotes ("tok"*)
    — inside them FTS5 treats it as a literal and silently matches nothing."""
    toks = re.findall(r"[A-Za-z0-9_*]+", query or "")
    if not toks:
        return None
    out = []
    for t in toks:
        if t.endswith("*") and len(t) > 1:
            out.append(f'"{t[:-1]}"*')
        else:
            out.append(f'"{t}"')
    return " ".join(out)


def trust_bonus(tier: str) -> float:
    return TRUST_BONUS.get(tier, 0.0)


def rank_terms(rec_trust, transfer_history, fail_penalty, fts, tag) -> float:
    """score = fts + tag + 0.5*transfer_history - 2.0*fail_penalty + trust bonus.
    No age term (rev 2): ttl_days handles staleness; overdue records are flagged, not buried."""
    return float(fts) + 1.0 * float(tag) + 0.5 * float(transfer_history) \
        - 2.0 * float(fail_penalty) + trust_bonus(rec_trust)


def transfer_history(outcomes: list) -> float:
    confirmed = sum(1 for o in outcomes if o["verdict"] == "confirmed")
    other = len(outcomes) - confirmed
    return (2.0 * confirmed - 0.5 * other) / (len(outcomes) + 1)


def fail_penalty(outcomes: list, profile: str, record_version=None) -> float:
    """Negative-verdict penalty on similar profiles. Verdicts earned against a
    different record_version are skipped: a stale verdict must not poison a
    fixed record (design rev 2, ledger rule)."""
    if not profile:
        return 0.0
    now = _dt.datetime.now(_dt.timezone.utc)
    total = 0.0
    for o in outcomes:
        if record_version is not None and o.get("record_version") is not None \
                and o["record_version"] != record_version:
            continue
        if o["verdict"] not in NEGATIVE_VERDICTS or not profile_similar(o.get("profile", ""), profile):
            continue
        try:
            ts = _dt.datetime.strptime(o["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
            age_days = max(0.0, (now - ts).total_seconds() / 86400.0)
        except (KeyError, ValueError):
            age_days = 0.0
        total += 1.0 / (1.0 + age_days / 30.0)
    return total


def ttl_overdue(rec: dict, updated: str) -> bool:
    """F-4: flag records past their ttl_days instead of silently burying them."""
    try:
        upd = _dt.datetime.strptime(updated, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
        age_days = (_dt.datetime.now(_dt.timezone.utc) - upd).total_seconds() / 86400.0
        return age_days > float(rec.get("ttl_days", 365))
    except (ValueError, TypeError, KeyError):
        return False


# ---------------------------------------------------------------- Phase 2: capture signing
# R2-1: binding proves a capture NAMES its record; the signature proves the KEY HOLDER
# produced it. The key lives outside the store; gates fail closed without it.

_ED25519_PATH = Path(__file__).resolve().parent / "ed25519.py"


def _load_ed25519():
    if not _ED25519_PATH.exists():
        raise FileNotFoundError("tools/ed25519.py missing — capture signing unavailable")
    spec = _ilu.spec_from_file_location("graft_ed25519", _ED25519_PATH)
    mod = _ilu.module_from_spec(spec)
    # R3-4: no .pyc residue inside the store from loading the curve code
    saved = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = saved
    return mod


_ED_CACHE = None


def _ed():
    """R3-3: lazy — find/stats/verify-table never touch the curve code; a missing
    ed25519.py degrades signing commands to a clean fail-closed message, it does
    not brick non-signing ones."""
    global _ED_CACHE
    if _ED_CACHE is None:
        _ED_CACHE = _load_ed25519()
    return _ED_CACHE


def resolve_keyfile(root: Path, override) -> Path:
    """Signing key location, outside the store: --sign-key > $GRAFT_SIGNING_KEY >
    <root>-signing.key (sibling of the tree)."""
    if override:
        return Path(override)
    env = os.environ.get("GRAFT_SIGNING_KEY")
    if env:
        return Path(env)
    return root.parent / f"{root.name}-signing.key"


def key_id_for(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()[:16]


def load_key(keyfile: Path):
    data = json.loads(keyfile.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("alg") != "ed25519":
        raise ValueError("unsupported or malformed key file")
    priv = bytes.fromhex(data["priv"])
    pub = bytes.fromhex(data["pub"])
    if len(priv) != 32 or len(pub) != 32:
        raise ValueError("key fields must be 32 bytes each")
    return priv, pub, data.get("key_id")


def verify_capture_sig(cap: Path, sig_path: Path, keyfile: Path):
    """R3-1: malformed signatures and keyfiles fail CLOSED with a clean message —
    never a traceback, never a crashed rebuild. The checks that fire first (key_id,
    content hash) are attacker-computable, so every later field must be guarded too."""
    try:
        key = json.loads(keyfile.read_text(encoding="utf-8"))
        sig = json.loads(sig_path.read_text(encoding="utf-8"))
        cap_bytes = cap.read_bytes()
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        return False, f"unreadable key or signature: {e}"
    if not isinstance(key, dict) or not isinstance(sig, dict):
        return False, "malformed key or signature file (not a JSON object)"
    if key.get("alg") != "ed25519":
        return False, "unsupported key alg"
    if sig.get("alg") != "ed25519":
        return False, "unsupported signature alg"
    if sig.get("key_id") != key.get("key_id"):
        return False, (f"signature by key {sig.get('key_id')} is not the store key "
                       f"{key.get('key_id')}")
    if sig.get("msg_sha256") != hashlib.sha256(cap_bytes).hexdigest():
        return False, "capture content changed after signing"
    try:
        pub = bytes.fromhex(key["pub"])
        sig_bytes = bytes.fromhex(sig["sig"])
    except (KeyError, ValueError, TypeError):
        return False, "malformed signature file (bad hex)"
    if len(pub) != 32:
        return False, "store keyfile malformed (pub must be 32 bytes)"
    try:
        ok, reason = _ed().checkvalid(sig_bytes, cap_bytes, pub)
    except FileNotFoundError as e:
        return False, f"{e} — restore tools/ed25519.py (lock-sources --verify detects tampering)"
    return ok, reason or "signature mismatch"


def capture_signature_check(rec: dict, root: Path, keyfile: Path) -> str:
    """Phase 2 gate for reproduced_local: every cited capture must carry a valid
    ed25519 signature by the store's key. Runs AFTER provenance and binding."""
    ev = rec.get("evidence") or {}
    if ev.get("status") != "reproduced_local":
        return ""
    if not (keyfile and keyfile.exists()):
        return ("no signing key found — a local repro cannot be authenticated without the "
                f"store's signing key (looked for: {keyfile}); run `tdb keygen` and "
                "`tdb sign-capture <capture>`, or pass --sign-key / set GRAFT_SIGNING_KEY")
    for r in (ev.get("runs") or []):
        f = root / r
        sig_path = f.parent / (f.name + ".sig")
        if not sig_path.exists():
            return (f"capture {r} is unsigned — reproduced_local requires a capture signed "
                    f"by the store's key; run `tdb sign-capture {r}`")
        ok, reason = verify_capture_sig(f, sig_path, keyfile)
        if not ok:
            return f"capture {r}: signature verification failed ({reason})"
    return ""


def cmd_keygen(args, root: Path) -> int:
    keyfile = Path(args.keyfile) if args.keyfile else resolve_keyfile(root, None)
    if keyfile.exists() and not args.force:
        print(f"ERROR: {keyfile} already exists — refusing to overwrite a signing key "
              f"(rotation invalidates every signed capture); use --force", file=sys.stderr)
        return 2
    if keyfile.resolve().is_relative_to(root.resolve()):
        print(f"ERROR: the signing key must live OUTSIDE the store (got {keyfile}) — a key "
              f"inside the tree is attacker-controllable with store write access",
              file=sys.stderr)
        return 2
    seed = os.urandom(32)
    try:
        pub = _ed().publickey(seed)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.write_text(json.dumps({"alg": "ed25519", "priv": seed.hex(), "pub": pub.hex(),
                                   "key_id": key_id_for(pub), "created": now_utc(),
                                   "tool": "graft tdb keygen"}, indent=2) + "\n", encoding="utf-8")
    keyfile.chmod(0o600)
    print(f"keygen: {keyfile} (key_id {key_id_for(pub)}) — BACK THIS UP: it is the trust "
          f"anchor for every locally-verified record; losing it drops the top tier until "
          f"captures are re-signed")
    return 0


def cmd_sign_capture(args, root: Path) -> int:
    keyfile = Path(args.keyfile) if args.keyfile else resolve_keyfile(root, None)
    if not keyfile.exists():
        print(f"ERROR: no signing key at {keyfile} — run `tdb keygen` first "
              f"(or pass --keyfile / set GRAFT_SIGNING_KEY)", file=sys.stderr)
        return 2
    cap = Path(args.capture)
    if not cap.is_absolute():
        cap = root / args.capture
    try:
        rel = cap.resolve().relative_to(root.resolve())
    except ValueError:
        print(f"ERROR: capture must be inside the graft root: {args.capture}", file=sys.stderr)
        return 2
    if not cap.is_file():
        print(f"ERROR: no such capture file: {args.capture}", file=sys.stderr)
        return 2
    try:
        seed, pub, _ = load_key(keyfile)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, KeyError) as e:
        print(f"ERROR: bad keyfile {keyfile}: {e}", file=sys.stderr)
        return 2
    data = cap.read_bytes()
    try:
        sig = _ed().signature(seed, data)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    sig_path = cap.parent / (cap.name + ".sig")
    sig_path.write_text(json.dumps({"alg": "ed25519", "key_id": key_id_for(pub),
                                    "sig": sig.hex(),
                                    "msg_sha256": hashlib.sha256(data).hexdigest(),
                                    "ts": now_utc()}, indent=2) + "\n", encoding="utf-8")
    print(f"signed: {rel.as_posix()} (key_id {key_id_for(pub)}) -> {sig_path.name}")
    return 0


# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS tech(id TEXT PRIMARY KEY, json TEXT NOT NULL, trust TEXT NOT NULL,
                                record_version INT, origin TEXT, mech_key TEXT, updated TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS tech_mech ON tech(mech_key);
CREATE VIRTUAL TABLE IF NOT EXISTS tech_fts USING fts5(rid UNINDEXED, text, effects, langs, trust UNINDEXED);
CREATE TABLE IF NOT EXISTS tech_lang(tech_id TEXT, lang TEXT, kind TEXT);
CREATE TABLE IF NOT EXISTS tech_effect(tech_id TEXT, effect TEXT);
CREATE TABLE IF NOT EXISTS pre(tech_id TEXT, kind TEXT, expr TEXT, check_kind TEXT, check_spec TEXT);
CREATE TABLE IF NOT EXISTS outcome(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, tech_id TEXT,
                                   record_version INT, profile TEXT, verdict TEXT, oracle TEXT,
                                   cost_min REAL, evidence TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS outcome_tech ON outcome(tech_id);
"""


def db_connect(root: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(root / "index.sqlite")
    conn.executescript(SCHEMA)
    return conn


def index_record(conn, root: Path, rec: dict, stored_trust: str):
    rid = rec["id"]
    text = " ".join([rec["title"], rec["invariant_violated"],
                    " ".join(s["does"] for s in rec["mechanism"]),
                    " ".join(rec["transfer"]["hazards"])])
    effects = " ".join([rec["class"]["effect"]] + rec["class"]["cwe"])
    langs = " ".join([rec["langs"]["origin"]] + rec["langs"]["transferable"])
    conn.execute("DELETE FROM tech_fts WHERE rid = ?", (rid,))
    conn.execute("INSERT INTO tech_fts(rid, text, effects, langs, trust) VALUES (?,?,?,?,?)",
                 (rid, text, effects, langs, stored_trust))
    conn.execute("DELETE FROM tech_lang WHERE tech_id = ?", (rid,))
    conn.execute("INSERT INTO tech_lang VALUES (?,?,?)", (rid, rec["langs"]["origin"], "origin"))
    for lang in rec["langs"]["transferable"]:
        conn.execute("INSERT INTO tech_lang VALUES (?,?,?)", (rid, lang, "transferable"))
    conn.execute("DELETE FROM tech_effect WHERE tech_id = ?", (rid,))
    conn.execute("INSERT INTO tech_effect VALUES (?,?)", (rid, rec["class"]["effect"]))
    conn.execute("DELETE FROM pre WHERE tech_id = ?", (rid,))
    for pre in rec["preconditions"]:
        chk = pre.get("check") or {}
        conn.execute("INSERT INTO pre VALUES (?,?,?,?,?)",
                     (rid, pre["kind"], pre.get("expr", ""),
                      chk.get("kind", ""), json.dumps(chk.get("spec", {}))))


def ledger_append(root: Path, row: dict):
    led = root / "outcomes" / "ledger.jsonl"
    led.parent.mkdir(parents=True, exist_ok=True)
    with led.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def ledger_rows(root: Path) -> list:
    led = root / "outcomes" / "ledger.jsonl"
    if not led.exists():
        return []
    return [json.loads(l) for l in led.read_text(encoding="utf-8").splitlines() if l.strip()]


def provenance_check(rec: dict, root: Path) -> str:
    """Refuse records whose provenance claims a hash that does not match the file."""
    for p in rec.get("provenance", []):
        path, claimed = p.get("path"), p.get("sha256")
        if path and claimed:
            if not contained(root, path):
                return f"provenance path escapes the graft root: {path}"
            f = root / path
            if not f.exists():
                return f"provenance references missing file: {path}"
            if sha256_file(f) != claimed:
                return f"provenance hash mismatch for {path}"
    return ""


def evidence_binding_check(rec: dict, root: Path) -> str:
    """A record claiming reproduced_local may only cite probes-shaped captures that
    name the record's own id. This closes the raw-blob and borrowed-evidence bypasses.
    It does NOT establish capture authenticity: a probes-shaped file authored by the
    record's own writer is indistinguishable from a genuine run until Phase-2 capture
    signing exists — read locally-verified as 'executed here, assuming the store was
    not forged'. F-8 keeps the runs paths inside the graft root."""
    ev = rec.get("evidence") or {}
    if ev.get("status") != "reproduced_local":
        return ""
    for r in (ev.get("runs") or []):
        if not contained(root, r):
            return f"evidence run path escapes the graft root: {r}"
        f = root / r
        if not f.exists():
            continue  # validate_record refuses missing runs already
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return (f"evidence file {r} is not a probes-shaped capture — reproduced_local "
                    f"requires JSON with a non-empty probes[] naming record {rec['id']}")
        probes = data.get("probes") if isinstance(data, dict) else None
        if not (isinstance(probes, list) and probes):
            return (f"evidence file {r} lacks probes[] — reproduced_local requires a "
                    f"probes-shaped capture naming record {rec['id']}")
        if not any(isinstance(p, dict) and p.get("technique") == rec["id"] for p in probes):
            return (f"evidence file {r} does not reference record {rec['id']} — "
                    f"evidence must be bound to the citing record, not borrowed")
    return ""


# ---------------------------------------------------------------- commands

def cmd_init(args, root: Path) -> int:
    db_connect(root).close()
    led = root / "outcomes" / "ledger.jsonl"
    led.parent.mkdir(parents=True, exist_ok=True)
    led.touch(exist_ok=True)
    load_vocab(root)  # fail loudly if vocab is broken
    print(f"init OK: {root / 'index.sqlite'} (FTS5 + tech_lang + outcomes) + {led}")
    return 0


def cmd_add(args, root: Path) -> int:
    vocab = load_vocab(root)
    conn = db_connect(root)
    keyfile = resolve_keyfile(root, getattr(args, "sign_key", None))
    # F-11: two-phase and batch-atomic — phase 1 validates EVERYTHING (no writes);
    # a poison anywhere in the batch admits nothing.
    staged = []
    seen_keys = set()
    seen_ids = set()
    try:
        for path in args.records:
            p = Path(path)
            if not p.exists():
                print(f"ERROR: no such record file: {p}", file=sys.stderr)
                return 2
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                print(f"ERROR: {p}: invalid JSON: {e}", file=sys.stderr)
                return 2
            if not isinstance(rec, dict):
                print(f"ERROR: {p}: record file must contain a JSON object", file=sys.stderr)
                return 2
            errs = validate_record(rec, root, vocab)
            if errs:
                print(f"ERROR: {rec.get('id', p.name)} failed schema v4 validation:", file=sys.stderr)
                for e in errs:
                    print(f"  - {e}", file=sys.stderr)
                return 2
            pc = provenance_check(rec, root)
            if pc:
                print(f"ERROR: {rec['id']}: {pc}", file=sys.stderr)
                return 2
            eb = evidence_binding_check(rec, root)
            if eb:
                print(f"ERROR: {rec['id']}: {eb}", file=sys.stderr)
                return 2
            cs = capture_signature_check(rec, root, keyfile)
            if cs:
                print(f"ERROR: {rec['id']}: {cs}", file=sys.stderr)
                return 2
            key = mech_key(rec)
            if rec["id"] in seen_ids:
                print(f"ERROR: {rec['id']}: duplicate record id in this batch", file=sys.stderr)
                return 2
            if key in seen_keys:
                print(f"ERROR: {rec['id']}: duplicate mechanism (mech_key {key}) elsewhere "
                      f"in this batch; a clone is not a new technique", file=sys.stderr)
                return 2
            if conn.execute("SELECT id FROM tech WHERE id = ?", (rec["id"],)).fetchone():
                print(f"ERROR: {rec['id']}: duplicate record id", file=sys.stderr)
                return 2
            # R2-2: never silently overwrite the store — a fresh DB is not a license to
            # replace an existing canon file; re-adding the file at its own canon path stays legal.
            canon = root / "techniques" / f"{rec['id']}.json"
            if canon.exists() and p.resolve() != canon.resolve():
                print(f"ERROR: {rec['id']}: canon file techniques/{rec['id']}.json already exists — "
                      f"not overwriting the store; use a new id or reindex", file=sys.stderr)
                return 2
            row = conn.execute("SELECT id FROM tech WHERE mech_key = ?", (key,)).fetchone()
            if row:
                print(f"ERROR: {rec['id']}: duplicate mechanism (mech_key {key}) "
                      f"already recorded as {row[0]}; a clone is not a new technique", file=sys.stderr)
                return 2
            seen_ids.add(rec["id"])
            seen_keys.add(key)
            staged.append((p, rec, key))
        # phase 2: commit — nothing was written before this point
        added = 0
        for p, rec, key in staged:
            admissible = admissible_trust(rec, root)
            claimed = rec.get("trust", "untrusted")
            stored = claimed if TRUST_ORDER[claimed] <= TRUST_ORDER[admissible] else admissible
            if stored != claimed:
                print(f"DOWNGRADED: {rec['id']} claimed {claimed}, provenance admits {admissible} "
                      f"— stored quarantined as {stored}")
            canon = root / "techniques" / f"{rec['id']}.json"
            if p.resolve() != canon.resolve():
                canon.parent.mkdir(parents=True, exist_ok=True)
                canon.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
            conn.execute("INSERT INTO tech VALUES (?,?,?,?,?,?,?)",
                         (rec["id"], json.dumps(rec, sort_keys=True), stored,
                          rec["record_version"], rec["langs"]["origin"], key, now_utc()))
            index_record(conn, root, rec, stored)
            for ref in rec.get("combines_with", []):
                if not conn.execute("SELECT 1 FROM tech WHERE id = ?", (ref,)).fetchone():
                    print(f"note: {rec['id']} combines_with {ref} not yet in DB (advisory until added)")
            added += 1
            print(f"added {rec['id']} [{rec['class']['effect']}] trust={stored} mech_key={key}")
        conn.commit()
    finally:
        conn.close()
    print(f"add: {added} record(s) admitted (quarantine-by-default enforced, batch-atomic)")
    return 0


def cmd_find(args, root: Path) -> int:
    conn = db_connect(root)
    where, params = [], []
    if not args.include_quarantined:
        where.append("trust NOT IN (?, ?)")
        params += list(QUARANTINED)
    if args.effect:
        where.append("id IN (SELECT tech_id FROM tech_effect WHERE effect = ?)")
        params.append(args.effect)
    if args.lang:
        where.append("id IN (SELECT tech_id FROM tech_lang WHERE lang = ?)")
        params.append(args.lang)
    if args.auth:
        where.append("id IN (SELECT tech_id FROM pre WHERE kind = 'auth' AND lower(trim(expr)) = lower(?))")
        params.append(args.auth)
    sql = "SELECT id, json, trust, origin, record_version, updated FROM tech"
    if where:
        sql += " WHERE " + " AND ".join(where)
    rows = conn.execute(sql, params).fetchall()
    outcomes = {}
    for o in conn.execute("SELECT tech_id, ts, profile, verdict, record_version FROM outcome").fetchall():
        outcomes.setdefault(o[0], []).append(
            {"tech_id": o[0], "ts": o[1], "profile": o[2], "verdict": o[3],
             "record_version": o[4]})
    fts_scores = {}
    match = sanitize_match(args.fts or "")
    if match and rows:
        q = "SELECT rid, bm25(tech_fts) FROM tech_fts WHERE tech_fts MATCH ?"
        for rid, score in conn.execute(q, (match,)).fetchall():
            fts_scores[rid] = max(0.0, -float(score))
    conn.close()
    results = []
    for rid, blob, trust, origin, rec_version, updated in rows:
        rec = json.loads(blob)
        tag = 0.0
        if args.lang:
            tag += 0.5 if origin == args.lang else \
                (0.25 if args.lang in rec["langs"]["transferable"] else 0.0)
        if args.effect:
            tag += 0.25
        tag = min(tag, 1.0)
        occ = outcomes.get(rid, [])
        score = rank_terms(trust, transfer_history(occ),
                           fail_penalty(occ, args.profile or "", record_version=rec_version),
                           fts_scores.get(rid, 0.0), tag)
        results.append((score, rid, rec, trust, updated))
    results.sort(key=lambda r: (-r[0], r[1]))
    if args.json:
        print(json.dumps([{"id": rid, "score": round(s, 3), "trust": t,
                           "effect": rec["class"]["effect"], "title": rec["title"],
                           "origin": rec["langs"]["origin"],
                           "transferable": rec["langs"]["transferable"]}
                          for s, rid, rec, t, _u in results], indent=2))
        return 0
    for s, rid, rec, t, updated in results:
        caveat = "" if t in ("corroborated", "locally-verified") else " [QUARANTINED]"
        advisory = " (advisory: web-corroborated)" if t == "corroborated" else ""
        overdue = " [TTL OVERDUE]" if ttl_overdue(rec, updated) else ""
        print(f"{rid} [{rec['class']['effect']}] trust={t}{caveat}{advisory}{overdue} score={s:.2f} "
              f"langs={rec['langs']['origin']}->{','.join(rec['langs']['transferable']) or '-'} · {rec['title']}")
    return 0


def cmd_show(args, root: Path) -> int:
    f = root / "techniques" / f"{args.tech_id}.json"
    if not f.exists():
        print(f"ERROR: unknown technique {args.tech_id}", file=sys.stderr)
        return 2
    rec = json.loads(f.read_text(encoding="utf-8"))
    print(f"{rec['id']} — {rec['title']}")
    print(f"  trust: {rec['trust']} (admissible: {admissible_trust(rec, root)})  "
          f"mech_key: {mech_key(rec)}  schema: v{rec['schema_version']} r{rec['record_version']}")
    conn = db_connect(root)
    upd = conn.execute("SELECT updated FROM tech WHERE id = ?", (rec["id"],)).fetchone()
    conn.close()
    ttl_state = ("OVERDUE (re-verify before use)" if upd and ttl_overdue(rec, upd[0])
                 else "within window" if upd else "unknown (not indexed)")
    print(f"  ttl: {rec.get('ttl_days')} days — {ttl_state}")
    print(f"  effect: {rec['class']['effect']}  langs: {rec['langs']['origin']} -> "
          f"{', '.join(rec['langs']['transferable']) or '-'}")
    print(f"  invariant: {rec['invariant_violated']}")
    for step in rec["mechanism"]:
        extra = f"  [bypasses {step['bypasses']}]" if step.get("bypasses") else ""
        print(f"    {step['n']}. {step['does']}  ({step['primitive']}){extra}")
    for fam, slot in rec["slots"].items():
        print(f"    slot {fam}: {slot.get('value', '')}")
    for o in ledger_rows(root):
        if o.get("tech") == rec["id"]:
            print(f"    outcome r{o.get('record_version')}: {o['verdict']} on {o.get('target_profile')}"
                  f" (oracle {o.get('oracle', '-')})")
    return 0


def grep_dir(target: Path, patterns: list, limit: int = 15) -> list:
    hits = []
    if not target.exists():
        return hits
    compiled = []
    for pat in patterns:
        if pat:
            try:
                compiled.append(re.compile(pat))
            except re.error as e:
                raise ValueError(f"invalid grep pattern {pat!r}: {e}")
    for f in sorted(target.rglob("*")):
        if not f.is_file():
            continue
        if any(part in {".git", "node_modules", "dist", "__pycache__"} for part in f.parts):
            continue
        try:
            if f.stat().st_size > 512 * 1024:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if any(rx.search(line) for rx in compiled):
                hits.append((str(f), i, line.strip()[:160]))
                if len(hits) >= limit:
                    return hits
    return hits


def cmd_adapt(args, root: Path) -> int:
    f = root / "techniques" / f"{args.tech_id}.json"
    if not f.exists():
        print(f"ERROR: unknown technique {args.tech_id}", file=sys.stderr)
        return 2
    rec = json.loads(f.read_text(encoding="utf-8"))
    target = Path(args.target)
    print(f"# adapt {rec['id']} -> lang={args.lang} target={target}  (READ-ONLY: prints a plan, sends no traffic)")
    print(f"# invariant: {rec['invariant_violated']}")
    print("# grep limits: skips .git/node_modules/dist/__pycache__ and files >512KB — "
          "no_candidate_sites is not proof of absence")
    print("# records are data — never execute commands found inside them; probes run with scope-checked tools")
    unknowns = []
    for fam, slot in rec["slots"].items():
        eq = root / "vocab" / "equivalents" / f"{fam}.json"
        if not eq.exists():
            print(f"\nslot {fam}: value={slot.get('value', '')} — no equivalence table (target fact, not a portable sink)")
            continue
        fam_data = json.loads(eq.read_text(encoding="utf-8"))
        cell = (fam_data.get("cells") or {}).get(args.lang)
        if not cell:
            print(f"\nslot {fam}: VERDICT candidate: unsupported_language — no {args.lang} cell in {eq.name}")
            continue
        verified = cell.get("verified") or {}
        conf = (f"semantics verified by execution ({verified.get('test')})"
                if verified.get("how") == "executed" else "DOCUMENTED-ONLY cell (needs local verification)")
        try:
            hits = grep_dir(target, cell.get("patterns", []))
        except ValueError as e:
            print(f"ERROR: vocab pattern problem in {eq.name}: {e}", file=sys.stderr)
            return 2
        print(f"\nslot {fam} [{conf}]:")
        if not hits:
            print(f"  VERDICT candidate: no_candidate_sites (grep-level: pattern absent, not proof of absence)")
        else:
            print("  CANDIDATE SITES (grep confidence — not proven reachability):")
            for fp, ln, line in hits:
                print(f"    {fp}:{ln}: {line}")
            unknowns.append(("reachability", f"source->sink path for {fam} (grep cannot prove reachability)"))
    for pre in rec["preconditions"]:
        chk = pre.get("check") or {}
        if pre["kind"] in INSTRUMENTAL and chk.get("kind") == "manual":
            unknowns.append(("manual", f"{pre['kind']}: {pre.get('expr', '')} (manual check)"))
        if pre["kind"] == "auth" and pre.get("expr", "none") not in ("none", "") and not chk:
            unknowns.append(("auth", f"{pre.get('expr', '')} — confirm on target"))
    print(f"\nunknowns[] ({len(unknowns)}):")
    for kind, text in unknowns:
        print(f"  - [{kind}] {text}")
    ORACLE_FOR_UNKNOWN = {
        "reachability": ("static", "trace the call chain from the candidate site to a request entrypoint"),
        "auth": ("static", "read the endpoint's auth requirement from routes/middleware/config"),
        "manual": ("local_repro", "answer the manual precondition with a minimal local experiment"),
    }
    print("\nexperiments (one experiment per unknown, cheapest sufficient oracle first):")
    for i, (kind, text) in enumerate(unknowns, 1):
        oracle, how = ORACLE_FOR_UNKNOWN.get(kind, ("local_repro", "minimal local experiment"))
        print(f"  {i}. [{oracle}] {text} — {how}")
    gate = rec["evidence"].get("gate")
    print(f"\nproof gate: {gate}"
          + (" — zero-day: external oracle only (callback/sanitizer/crash, independently replicated)"
             if gate == "external_oracle" else
             " — known-CVE/patch-derived: differential (pre-patch trigger, post-patch silence)"))
    print("outcomes: record every verdict (win or lose) via: tdb outcome "
          f"{rec['id']} --verdict <v> --target-profile <lang>/<framework> [--oracle <o>]")
    return 0


def cmd_outcome(args, root: Path) -> int:
    if args.verdict not in VERDICTS:
        print(f"ERROR: verdict must be one of {sorted(VERDICTS)}", file=sys.stderr)
        return 2
    if args.oracle and args.oracle not in ORACLES:
        print(f"ERROR: oracle must be one of {ORACLES}", file=sys.stderr)
        return 2
    f = root / "techniques" / f"{args.tech_id}.json"
    if not f.exists():
        print(f"ERROR: unknown technique {args.tech_id}", file=sys.stderr)
        return 2
    # R2-4: the ledger is the source of truth — no rows for records the admission gate
    # refused or that were never added; check the index, not just the file on disk.
    conn = db_connect(root)
    try:
        if not conn.execute("SELECT 1 FROM tech WHERE id = ?", (args.tech_id,)).fetchone():
            print(f"ERROR: {args.tech_id} is not in the index (gate refused or never added) — "
                  f"reindex/fix before recording outcomes", file=sys.stderr)
            return 2
    finally:
        conn.close()
    rec = json.loads(f.read_text(encoding="utf-8"))
    try:
        cost_min = float(args.cost_min) if args.cost_min else 0.0
    except ValueError:
        print("ERROR: --cost-min must be a number", file=sys.stderr)
        return 2
    if args.slots_json:
        try:
            slots = json.loads(args.slots_json)
        except json.JSONDecodeError as e:
            print(f"ERROR: --slots-json is not valid JSON: {e}", file=sys.stderr)
            return 2
        if not isinstance(slots, dict):
            print("ERROR: --slots-json must be a JSON object", file=sys.stderr)
            return 2
    else:
        slots = {}
    conn = db_connect(root)
    row = {"ts": now_utc(), "tech": args.tech_id, "record_version": rec["record_version"],
           "target_profile": args.target_profile, "verdict": args.verdict,
           "oracle": args.oracle or "none", "cost_min": cost_min,
           "evidence": args.evidence or "", "slots": slots,
           "note": args.note or ""}
    ledger_append(root, row)
    conn.execute("INSERT INTO outcome(ts, tech_id, record_version, profile, verdict, oracle, "
                 "cost_min, evidence, note) VALUES (?,?,?,?,?,?,?,?,?)",
                 (row["ts"], row["tech"], row["record_version"], row["target_profile"],
                  row["verdict"], row["oracle"], row["cost_min"], row["evidence"], row["note"]))
    conn.commit()
    conn.close()
    print(f"outcome: {args.tech_id} r{row['record_version']} {args.verdict} on "
          f"{args.target_profile} (oracle {row['oracle']}) — negative results are mandatory output")
    return 0


def cmd_promote(args, root: Path) -> int:
    conn = db_connect(root)
    if not conn.execute("SELECT 1 FROM tech WHERE id = ?", (args.tech_id,)).fetchone():
        conn.close()
        print(f"ERROR: {args.tech_id} is not in the index — promote operates on admitted "
              f"records only (run tdb add first)", file=sys.stderr)
        return 2
    conn.close()
    f = root / "techniques" / f"{args.tech_id}.json"
    if not f.exists():
        print(f"ERROR: {args.tech_id} is indexed but its record file is missing "
              f"(restore it or reindex)", file=sys.stderr)
        return 2
    rec = json.loads(f.read_text(encoding="utf-8"))
    if not isinstance(rec, dict):
        print(f"ERROR: {args.tech_id}: record file must contain a JSON object", file=sys.stderr)
        return 2
    for check in (provenance_check, evidence_binding_check):
        msg = check(rec, root)
        if msg:
            print(f"ERROR: {args.tech_id}: {msg}", file=sys.stderr)
            return 2
    cs = capture_signature_check(rec, root, resolve_keyfile(root, getattr(args, "sign_key", None)))
    if cs:
        print(f"ERROR: {args.tech_id}: {cs}", file=sys.stderr)
        return 2
    admissible = admissible_trust(rec, root)
    if not args.to:
        print(f"ERROR: specify --to <tier>. Current: {rec.get('trust')}  Admissible: {admissible}",
              file=sys.stderr)
        return 2
    if args.to not in TRUST_ORDER:
        print(f"ERROR: --to must be one of {sorted(TRUST_ORDER)}", file=sys.stderr)
        return 2
    if TRUST_ORDER[args.to] > TRUST_ORDER[admissible]:
        print(f"ERROR: promotion refused — {args.tech_id} provenance admits {admissible}, not {args.to}. "
              "Locally-verified requires evidence.status=reproduced_local with runs files that exist; "
              "corroborated requires 2+ distinct authors and zero manual instrumental checks.",
              file=sys.stderr)
        return 1
    rec["trust"] = args.to
    rec["record_version"] += 1
    f.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    conn = db_connect(root)
    conn.execute("UPDATE tech SET trust = ?, record_version = ?, json = ?, updated = ? WHERE id = ?",
                 (args.to, rec["record_version"], json.dumps(rec, sort_keys=True),
                  now_utc(), args.tech_id))
    conn.commit()
    conn.close()
    print(f"promoted {args.tech_id} -> {args.to} (record_version {rec['record_version']})")
    return 0


def cmd_verify_table(args, root: Path) -> int:
    fam_files = sorted((root / "vocab" / "equivalents").glob("*.json"))
    executed, skipped, failed, documented = 0, 0, 0, []
    for fam_file in fam_files:
        fam = json.loads(fam_file.read_text(encoding="utf-8"))
        for lang, cell in sorted((fam.get("cells") or {}).items()):
            verified = cell.get("verified") or {}
            if verified.get("how") == "executed":
                test_rel = verified["test"]
                test = root / test_rel
                interp = INTERP.get(test.suffix)
                if not test_rel.startswith("tests/equiv/") or not contained(root, test_rel):
                    print(f"{fam['family']}/{lang}: INVALID TEST PATH {test_rel} "
                          "(executed cells must declare tests under tests/equiv/)")
                    failed += 1
                    continue
                if not test.exists() or not interp:
                    print(f"{fam['family']}/{lang}: MISSING TEST {verified['test']}")
                    failed += 1
                    continue
                resolved_interp = interp if Path(interp).is_absolute() else shutil.which(interp)
                if not resolved_interp:
                    skipped += 1
                    print(f"{fam['family']}/{lang}: SKIPPED ({interp} not installed locally — needs local runtime)")
                    continue
                env = {**os.environ, "PYTHONUTF8": "1"}
                r = subprocess.run([resolved_interp, str(test)], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", env=env, timeout=30)
                executed += 1
                if r.returncode != 0:
                    failed += 1
                print(f"{fam['family']}/{lang}: executed {test.name}: "
                      f"{'PASS' if r.returncode == 0 else 'FAIL'}")
            else:
                documented.append(f"{fam['family']}/{lang}")
    if skipped:
        print(f"\nverify-table: {executed} executed cells verified, {skipped} skipped (missing runtime), {failed} failed")
    else:
        print(f"\nverify-table: {executed} executed cells verified, {failed} failed")
    print(f"documented cells (needs_local_verification): {len(documented)} — " + ", ".join(documented))
    print("documented cells are doc-based knowledge (java/dotnet/go/rust lack interpreters here); "
          "never present them as executed")
    return 1 if (failed or (getattr(args, "strict", False) and skipped)) else 0


def manifest_paths(root: Path) -> list:
    """R2-3: the manifest covers knowledge data AND the gate's own code, unit tests and
    docs — a tampered verifier must not pass a tamper-evidence check. Bytecode and the
    staging area (drafts/) stay out; index.sqlite is derived state."""
    out = []
    for sub in ("techniques", "vocab", "probes", "tests/equiv", "outcomes", "sources", "tools",
                "skills", ".agents", ".claude-plugin", "rules", "assets", "scripts"):
        base = root / sub
        if base.exists():
            out += [p for p in sorted(base.rglob("*")) if p.is_file()
                    and "__pycache__" not in p.parts and not p.name.endswith(".pyc")]
    out += [p for p in sorted((root / "tests").glob("*.py")) if p.is_file()]
    for doc in ("README.md", "SKILL.md", "AGENTS.md", "LICENSE", "NOTICE",
                "SECURITY.md", "pyproject.toml", "plugin.json"):
        if (root / doc).exists():
            out.append(root / doc)
    return sorted(set(out))


def cmd_lock_sources(args, root: Path) -> int:
    lock = root / "sources.lock"
    if args.verify:
        if not lock.exists():
            print("ERROR: sources.lock missing — run lock-sources first", file=sys.stderr)
            return 1
        manifest = json.loads(lock.read_text(encoding="utf-8"))["files"]
        current = {p.relative_to(root).as_posix(): sha256_file(p) for p in manifest_paths(root)}
        bad = [k for k in set(manifest) | set(current) if manifest.get(k) != current.get(k)]
        if bad:
            print("ERROR: manifest verification failed for:", file=sys.stderr)
            for k in sorted(bad):
                print(f"  - {k}", file=sys.stderr)
            return 1
        print(f"sources.lock verified: {len(current)} files match the sha256 manifest")
        return 0
    files = {p.relative_to(root).as_posix(): sha256_file(p) for p in manifest_paths(root)}
    lock.write_text(json.dumps({"generated": now_utc(), "files": files}, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    print(f"sources.lock written: {len(files)} files hashed (tamper-evident manifest)")
    return 0


def cmd_reindex(args, root: Path) -> int:
    vocab = load_vocab(root)
    keyfile = resolve_keyfile(root, getattr(args, "sign_key", None))
    conn = sqlite3.connect(root / "index.sqlite")
    conn.executescript("DROP TABLE IF EXISTS tech; DROP TABLE IF EXISTS tech_fts;"
                       "DROP TABLE IF EXISTS tech_lang; DROP TABLE IF EXISTS tech_effect;"
                       "DROP TABLE IF EXISTS pre; DROP TABLE IF EXISTS outcome;")
    conn.close()
    conn = db_connect(root)
    n = 0
    violations = 0
    for f in sorted((root / "techniques").glob("T-*.json")):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"ERROR: {f.name}: invalid JSON ({e}) — SKIPPED", file=sys.stderr)
            violations += 1
            continue
        if not isinstance(rec, dict):
            print(f"ERROR: {f.name}: record file must contain a JSON object — SKIPPED", file=sys.stderr)
            violations += 1
            continue
        errs = validate_record(rec, root, vocab)
        if errs:
            print(f"ERROR: {rec.get('id')}: schema invalid, SKIPPED: {errs}", file=sys.stderr)
            violations += 1
            continue
        # F-1: the rebuild path runs the same gates as add — a poison file must
        # not ride reindex into the index, let alone the top trust tier.
        gate_msg = provenance_check(rec, root) or evidence_binding_check(rec, root) \
            or capture_signature_check(rec, root, keyfile)
        if gate_msg:
            print(f"ERROR: {rec.get('id')}: {gate_msg} — SKIPPED", file=sys.stderr)
            violations += 1
            continue
        admissible = admissible_trust(rec, root)
        claimed = rec.get("trust", "untrusted")
        stored = claimed if TRUST_ORDER[claimed] <= TRUST_ORDER[admissible] else admissible
        conn.execute("INSERT OR REPLACE INTO tech VALUES (?,?,?,?,?,?,?)",
                     (rec["id"], json.dumps(rec, sort_keys=True), stored,
                      rec["record_version"], rec["langs"]["origin"], mech_key(rec), now_utc()))
        index_record(conn, root, rec, stored)
        n += 1
    rows = ledger_rows(root)
    for row in rows:
        conn.execute("INSERT INTO outcome(ts, tech_id, record_version, profile, verdict, oracle, "
                     "cost_min, evidence, note) VALUES (?,?,?,?,?,?,?,?,?)",
                     (row.get("ts", ""), row.get("tech"), row.get("record_version", 1),
                      row.get("target_profile", ""), row.get("verdict"), row.get("oracle", ""),
                      float(row.get("cost_min", 0)), row.get("evidence", ""), row.get("note", "")))
    conn.commit()
    conn.close()
    print(f"reindex: rebuilt from {n} technique record(s) + {len(rows)} ledger row(s) "
          "(index.sqlite is derived state; ledger.jsonl is the source of truth)")
    if violations:
        print(f"reindex: {violations} record(s) REFUSED by the gate and skipped — "
              "fix or remove them; the index is only as trustworthy as the store",
              file=sys.stderr)
        return 2
    return 0


def cmd_distill(args, root: Path) -> int:
    """Phase 1 pipeline: stage a source artifact, emit a draft + fill checklist.
    Drafts never admit themselves; admission is mv -> techniques/ -> tdb add (the gate)."""
    if args.list:
        ddir = root / "drafts"
        if not ddir.exists() or not list(ddir.glob("T-*.draft.json")):
            print("no drafts")
            return 0
        for f in sorted(ddir.glob("T-*.draft.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            prov = (d.get("provenance") or [{}])[0]
            print(f"{d['id']} (draft) · {d.get('title', '')} · from {prov.get('src', '?')}")
        return 0
    if not args.src or not args.author or not args.title:
        print("ERROR: distill requires --from <artifact> --author <author> --title <title> (or --list)",
              file=sys.stderr)
        return 2
    art = Path(args.src)
    if not art.exists():
        print(f"ERROR: no such source artifact: {art}", file=sys.stderr)
        return 2
    if not art.is_file():
        print(f"ERROR: source must be a regular file: {art}", file=sys.stderr)
        return 2
    digest = sha256_file(art)
    sdir = root / "sources"
    sdir.mkdir(parents=True, exist_ok=True)
    staged = sdir / f"{digest[:16]}-{art.name}"
    if staged.exists():
        print(f"ERROR: source already staged as sources/{staged.name} — distill the record "
              f"from that staged copy; never stage the same artifact twice", file=sys.stderr)
        return 2
    shutil.copy(art, staged)
    ids = [f.stem for f in (root / "techniques").glob("T-*.json")] + \
          [f.stem.replace(".draft", "") for f in (root / "drafts").glob("T-*.draft.json")]
    nums = [int(i.split("-")[1]) for i in ids if re.fullmatch(r"T-\d{4}", i)]
    nid = f"T-{(max(nums) + 1) if nums else 1:04d}"
    draft = {
        "id": nid, "schema_version": SCHEMA_VERSION, "record_version": 1,
        "title": args.title, "index_line": "",
        "langs": {"origin": "", "transferable": []},
        "class": {"cwe": [], "capec": [], "effect": "", "stage": ""},
        "invariant_violated": "",
        "mechanism": [],
        "slots": {},
        "preconditions": [],
        "observables": {"success": [], "failure_like": [], "false_positive": []},
        "transfer": {"same_effect": [], "hazards": [], "non_transfers": [], "confidence": {}},
        "combines_with": [],
        "probes": [],
        "evidence": {"status": "external_reported", "gate": "external_oracle", "runs": [], "target": ""},
        "provenance": [{"src": f"sources/{staged.name}", "author": args.author,
                        "sha256": digest, "corroborates": "method detail"}],
        "trust": "untrusted",
        "confidence": {"curator": 0.0},
        "cost": {"attempts": 0, "wall_min": 0, "noise": "unknown"},
        "ttl_days": 365,
    }
    ddir = root / "drafts"
    ddir.mkdir(exist_ok=True)
    dpath = ddir / f"{nid}.draft.json"
    dpath.write_text(json.dumps(draft, indent=2) + "\n", encoding="utf-8")
    errs = validate_record(draft, root, load_vocab(root))
    print(f"distill: staged sources/{staged.name} (sha256 {digest[:16]}…) -> {dpath}")
    print(f"draft {nid} is INCOMPLETE by design — the curator fills it; admission only via tdb add")
    print("fill checklist (schema v4 violations to resolve):")
    for e in errs:
        print(f"  - {e}")
    print(f"when done: mv drafts/{nid}.draft.json techniques/{nid}.json && "
          f"tdb add techniques/{nid}.json (the gate applies)")
    return 0


def cmd_stats(args, root: Path) -> int:
    conn = db_connect(root)
    print("trust histogram:")
    for tier in ("locally-verified", "corroborated", "single-source", "untrusted"):
        n = conn.execute("SELECT COUNT(*) FROM tech WHERE trust = ?", (tier,)).fetchone()[0]
        print(f"  {tier}: {n}")
    print("effects:")
    for eff, n in conn.execute("SELECT effect, COUNT(*) FROM tech_effect GROUP BY effect "
                               "ORDER BY COUNT(*) DESC"):
        print(f"  {eff}: {n}")
    rows = ledger_rows(root)
    print(f"ledger: {len(rows)} attempt(s)")
    dead = [o for o in rows if o["verdict"] in NEGATIVE_VERDICTS]
    if dead:
        print("dead ends (negative knowledge — as valuable as wins):")
        for o in dead:
            print(f"  {o['tech']} r{o.get('record_version')}: {o['verdict']} on {o.get('target_profile')}")
    # F-1: the poison-gate re-check runs over the FILES (the store is the truth),
    # re-running binding + provenance + the over-claim check per record.
    violations = 0
    file_ids = set()
    for f in sorted((root / "techniques").glob("T-*.json")):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            print(f"  poison-gate violation: {f.stem}: unparseable record file")
            violations += 1
            continue
        if not isinstance(rec, dict):
            print(f"  poison-gate violation: {f.stem}: record file is not a JSON object")
            violations += 1
            continue
        file_ids.add(rec["id"])
        for check in (provenance_check, evidence_binding_check,
                      lambda r, rt: capture_signature_check(
                          r, rt, resolve_keyfile(root, getattr(args, "sign_key", None)))):
            msg = check(rec, root)
            if msg:
                print(f"  poison-gate violation: {rec['id']}: {msg}")
                violations += 1
                break
        else:
            if TRUST_ORDER[rec.get("trust", "untrusted")] > TRUST_ORDER[admissible_trust(rec, root)]:
                print(f"  poison-gate violation: {rec['id']} stored trust exceeds provenance")
                violations += 1
    for (rid,) in conn.execute("SELECT id FROM tech").fetchall():
        if rid not in file_ids:
            print(f"  poison-gate violation: {rid} indexed but no record file (stale index — reindex)")
            violations += 1
    print(f"poison gate: {'OK' if violations == 0 else 'VIOLATIONS: ' + str(violations)} "
          "(binding + provenance + over-claim re-run over the record files)")
    overdue = 0
    for rid, blob, updated in conn.execute("SELECT id, json, updated FROM tech").fetchall():
        if ttl_overdue(json.loads(blob), updated):
            overdue += 1
    print(f"ttl: {overdue} record(s) OVERDUE (flagged [TTL OVERDUE] in find; re-verify before use)")
    conn.close()
    return 0


def resolve_default_root() -> Path:
    """Resolve GRAFT store root: $GRAFT_ROOT > script's parent tree > current working dir."""
    env_root = os.environ.get("GRAFT_ROOT", "").strip()
    if env_root:
        return Path(env_root)
    script_parent = Path(__file__).resolve().parent.parent
    if (script_parent / "vocab" / "effects.json").is_file():
        return script_parent
    cwd = Path.cwd()
    if (cwd / "vocab" / "effects.json").is_file():
        return cwd
    return script_parent


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    default_root = resolve_default_root()
    ap = argparse.ArgumentParser(prog="tdb", description="GRAFT technique DB (offline, stdlib-only)")
    ap.add_argument("--root", default=str(default_root),
                    help="graft tree root (default: $GRAFT_ROOT, script's parent, or cwd)")
    ap.add_argument("--sign-key", default=None,
                    help="ed25519 signing key path (default: $GRAFT_SIGNING_KEY or <root>-signing.key)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create index.sqlite + empty ledger (idempotent)")
    p = sub.add_parser("add", help="validate, gate trust, index records")
    p.add_argument("records", nargs="+")
    p = sub.add_parser("find", help="hard-filter then rank")
    p.add_argument("--effect"); p.add_argument("--lang"); p.add_argument("--auth")
    p.add_argument("--fts"); p.add_argument("--profile", help="target profile <lang>/<framework>")
    p.add_argument("--include-quarantined", action="store_true")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("show"); p.add_argument("tech_id")
    p = sub.add_parser("adapt"); p.add_argument("tech_id")
    p.add_argument("--target", required=True); p.add_argument("--lang", required=True)
    p = sub.add_parser("outcome"); p.add_argument("tech_id")
    p.add_argument("--verdict", required=True); p.add_argument("--target-profile", required=True)
    p.add_argument("--oracle"); p.add_argument("--cost-min"); p.add_argument("--evidence")
    p.add_argument("--slots-json"); p.add_argument("--note")
    p = sub.add_parser("promote"); p.add_argument("tech_id"); p.add_argument("--to")
    p = sub.add_parser("distill", help="stage a source artifact and emit a gated draft")
    p.add_argument("--from", dest="src", help="source artifact (advisory/patch/write-up)")
    p.add_argument("--author"); p.add_argument("--title")
    p.add_argument("--list", action="store_true", help="list drafts")
    p = sub.add_parser("verify-table", help="re-run executed equivalence cells; exit 1 on regression")
    p.add_argument("--strict", action="store_true", help="exit non-zero if any runtime is missing")
    p = sub.add_parser("lock-sources"); p.add_argument("--verify", action="store_true")
    sub.add_parser("reindex", help="rebuild index.sqlite from techniques/ + ledger.jsonl")
    sub.add_parser("stats")
    p = sub.add_parser("keygen", help="create the store's ed25519 signing key (outside the tree)")
    p.add_argument("--keyfile", help="key path (default: <root>-signing.key)")
    p.add_argument("--force", action="store_true", help="overwrite an existing key (invalidates signed captures)")
    p = sub.add_parser("sign-capture", help="sign an evidence capture with the store's key")
    p.add_argument("capture", help="capture file, relative to the root")
    p.add_argument("--keyfile", help="key path (default: <root>-signing.key)")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    return {"init": cmd_init, "add": cmd_add, "find": cmd_find, "show": cmd_show,
            "adapt": cmd_adapt, "outcome": cmd_outcome, "promote": cmd_promote,
            "verify-table": cmd_verify_table, "lock-sources": cmd_lock_sources,
            "distill": cmd_distill,
            "reindex": cmd_reindex, "stats": cmd_stats,
            "keygen": cmd_keygen, "sign-capture": cmd_sign_capture}[args.cmd](args, root)


if __name__ == "__main__":
    sys.exit(main())