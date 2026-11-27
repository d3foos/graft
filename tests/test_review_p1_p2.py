# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Regression tests for P1/P2 audit fixes in tools/tdb.py and tools/ed25519.py."""
from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GRAFT / "tools"))
import ed25519  # noqa: E402
import tdb  # noqa: E402


def run_tdb(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(root / "tools" / "tdb.py"), "--root", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def make_temp_store(tmp: str) -> Path:
    dst = Path(tmp) / "graft"
    for sub in ("tools", "vocab", "techniques", "probes"):
        shutil.copytree(GRAFT / sub, dst / sub)
    (dst / "outcomes").mkdir(parents=True, exist_ok=True)
    (dst / "outcomes" / "ledger.jsonl").write_text("", encoding="utf-8")
    return dst


class TestEd25519CanonicalZero(unittest.TestCase):
    def test_decodepoint_rejects_noncanonical_zero_with_sign_bit(self):
        # y = 1 => x = 0; setting the sign bit (MSB = 1) is non-canonical per RFC 8032 §5.1.3
        bad_point = bytes([1]) + bytes(30) + bytes([0x80])
        self.assertIsNone(ed25519._decodepoint(bad_point))
        ok, reason = ed25519.checkvalid(bad_point + bytes(32), b"msg", ed25519.publickey(bytes(32)))
        self.assertFalse(ok)
        self.assertEqual(reason, "point not on curve")


class TestTechIdContainment(unittest.TestCase):
    def test_traversal_tech_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_temp_store(tmp)
            assert run_tdb(root, "reindex").returncode == 0
            (root / "secret.json").write_text(json.dumps({"id": "T-0001"}), encoding="utf-8")
            for cmd in (
                ("show", "../secret"),
                ("adapt", "../secret", "--target", tmp, "--lang", "python"),
                ("outcome", "../secret", "--verdict", "no_sink", "--target-profile", "python/flask"),
                ("promote", "../secret", "--to", "corroborated"),
            ):
                r = run_tdb(root, *cmd)
                self.assertEqual(r.returncode, 2, f"{cmd} should fail cleanly: {r.stdout} {r.stderr}")
                self.assertNotIn("Traceback", r.stderr)


class TestAdaptPreconditionsAndPrune(unittest.TestCase):
    def test_adapt_runs_grep_precondition_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_temp_store(tmp)
            target = Path(tmp) / "app"
            (target / "src").mkdir(parents=True)
            (target / "src" / "handler.py").write_text(
                "import pickle\ndef load(cookie): return pickle.loads(cookie)\n",
                encoding="utf-8",
            )
            r = run_tdb(root, "adapt", "T-0007", "--target", str(target), "--lang", "python")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("precondition checks", r.stdout)
            self.assertIn("MATCHED", r.stdout)
            self.assertIn("pickle.loads", r.stdout)

    def test_grep_dir_prunes_node_modules_and_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            (target / "node_modules" / "pkg").mkdir(parents=True)
            (target / ".git").mkdir(parents=True)
            (target / "src").mkdir(parents=True)
            (target / "node_modules" / "pkg" / "bad.py").write_text("pickle.loads(x)\n", encoding="utf-8")
            (target / ".git" / "config").write_text("pickle.loads(x)\n", encoding="utf-8")
            (target / "src" / "ok.py").write_text("print('safe')\n", encoding="utf-8")
            hits = tdb.grep_dir(target, [r"pickle\.loads"])
            self.assertEqual(hits, [])


class TestPromoteFtsAndStatsStrict(unittest.TestCase):
    def test_promote_updates_tech_fts_trust(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_temp_store(tmp)
            # Downgrade T-0007 in-place to single-source, reindex, then promote to corroborated
            rec_path = root / "techniques" / "T-0007.json"
            rec = json.loads(rec_path.read_text(encoding="utf-8"))
            rec["trust"] = "single-source"
            rec_path.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
            assert run_tdb(root, "reindex").returncode == 0
            r = run_tdb(root, "promote", "T-0007", "--to", "corroborated")
            self.assertEqual(r.returncode, 0, r.stderr)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as conn:
                fts_trust = conn.execute("SELECT trust FROM tech_fts WHERE rid = 'T-0007'").fetchone()[0]
            self.assertEqual(fts_trust, "corroborated")

    def test_stats_strict_exits_nonzero_on_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_temp_store(tmp)
            assert run_tdb(root, "reindex").returncode == 0
            self.assertEqual(run_tdb(root, "stats", "--strict").returncode, 0)
            # Tamper T-0001 to claim locally-verified without signed runs
            rec_path = root / "techniques" / "T-0001.json"
            rec = json.loads(rec_path.read_text(encoding="utf-8"))
            rec["trust"] = "locally-verified"
            rec_path.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(run_tdb(root, "stats").returncode, 0)
            r_strict = run_tdb(root, "stats", "--strict")
            self.assertEqual(r_strict.returncode, 1)
            self.assertIn("VIOLATIONS", r_strict.stdout)


class TestFindFiltersAndEmptyIndexHint(unittest.TestCase):
    def test_empty_index_prints_hint_to_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_temp_store(tmp)
            r = run_tdb(root, "find")
            self.assertEqual(r.returncode, 0)
            self.assertIn("tdb reindex", r.stderr)

    def test_find_cwe_and_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_temp_store(tmp)
            assert run_tdb(root, "reindex").returncode == 0
            r_cwe = run_tdb(root, "find", "--cwe", "502", "--json")
            self.assertEqual(r_cwe.returncode, 0, r_cwe.stderr)
            rows = json.loads(r_cwe.stdout)
            self.assertTrue(any(row["id"] == "T-0007" for row in rows))
            r_lim = run_tdb(root, "find", "--effect", "EXEC", "--limit", "3", "--json")
            self.assertEqual(r_lim.returncode, 0, r_lim.stderr)
            self.assertEqual(len(json.loads(r_lim.stdout)), 3)


if __name__ == "__main__":
    unittest.main()
