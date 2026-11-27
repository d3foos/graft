# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""End-to-end CLI: init/add/find/show/outcome/promote/stats/lock-sources/reindex on a temp copy."""
import contextlib, json, shutil, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent

def run(root, *args, input=None):
    return subprocess.run([sys.executable, str(Path(root) / "tools" / "tdb.py"),
                           "--root", str(root), *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", input=input)

class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "graft"
        shutil.copytree(GRAFT, cls.root, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock", "__pycache__"))
        r = run(cls.root, "init")
        assert r.returncode == 0, r.stderr
        # Phase-2 fixture: key + signed captures if present
        r = run(cls.root, "keygen", "--keyfile", str(Path(cls.tmp.name) / "graft-signing.key"))
        assert r.returncode == 0, r.stderr
        for cap in sorted((cls.root / "outcomes").glob("*.json")):
            if cap.name != "ledger.jsonl":
                assert run(cls.root, "sign-capture", str(cap.relative_to(cls.root))).returncode == 0
        r = run(cls.root, "add", *[str(p) for p in sorted((cls.root / "techniques").glob("T-*.json"))])
        assert r.returncode == 0, r.stderr

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_shipped_corpus_admitted(self):
        r = run(self.root, "stats")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("poison gate: OK", r.stdout)
        self.assertIn("untrusted: 0", r.stdout)
        self.assertIn("locally-verified: 0", r.stdout)
        total = len(list((self.root / "techniques").glob("T-*.json")))
        self.assertGreaterEqual(total, 95)

    def test_find_effect_lang(self):
        r = run(self.root, "find", "--effect", "SQL_EXEC", "--lang", "node")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("T-0001", r.stdout)
        self.assertIn("T-0002", r.stdout)

    def test_find_exec_php(self):
        r = run(self.root, "find", "--effect", "EXEC", "--lang", "php")
        self.assertIn("T-0005", r.stdout)
        self.assertIn("T-0007", r.stdout)

    def test_hostile_fts_no_crash_no_mutation(self):
        with contextlib.closing(sqlite3.connect(self.root / "index.sqlite")) as db:
            before = db.execute("SELECT COUNT(*) FROM tech").fetchone()[0]
        r = run(self.root, "find", "--effect", "SQL_EXEC", "--fts", '"; DROP TABLE tech; --')
        self.assertEqual(r.returncode, 0, r.stderr)
        with contextlib.closing(sqlite3.connect(self.root / "index.sqlite")) as db:
            after = db.execute("SELECT COUNT(*) FROM tech").fetchone()[0]
        self.assertEqual(before, after)

    def test_outcome_row_carries_record_version(self):
        r = run(self.root, "outcome", "T-0001", "--verdict", "no_sink",
                "--target-profile", "php8.2/laravel", "--oracle", "static", "--cost-min", "6")
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = [json.loads(l) for l in (self.root / "outcomes" / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if l]
        self.assertEqual(rows[-1]["tech"], "T-0001")
        expected_version = json.loads((self.root / "techniques" / "T-0001.json").read_text(encoding="utf-8"))["record_version"]
        self.assertEqual(rows[-1]["record_version"], expected_version,
                         "ledger row must carry the version it was earned against")
        self.assertEqual(rows[-1]["verdict"], "no_sink")

    def test_fail_penalty_ranks_similar_lower(self):
        run(self.root, "outcome", "T-0001", "--verdict", "no_sink",
            "--target-profile", "php8.2/laravel", "--oracle", "static")
        r = run(self.root, "find", "--effect", "SQL_EXEC", "--lang", "php",
                "--profile", "php8.2/laravel")
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [l for l in r.stdout.splitlines() if l.startswith("T-")]
        self.assertTrue(lines, r.stdout)
        ids = [l.split()[0] for l in lines]
        # corpus-robust: what matters is the RELATIVE order of the penalised record and a
        # comparable unpenalised one, not which record happens to sit at position 0.
        self.assertIn("T-0001", ids, r.stdout)
        self.assertIn("T-0002", ids, r.stdout)
        self.assertGreater(ids.index("T-0001"), ids.index("T-0002"),
                           "penalised T-0001 must rank below the unpenalised T-0002")

    def test_show(self):
        r = run(self.root, "show", "T-0001")
        self.assertIn("User string concatenated into SQL", r.stdout)
        rec = json.loads((self.root / "techniques" / "T-0001.json").read_text(encoding="utf-8"))
        self.assertIn(rec["trust"], r.stdout, "shown trust must match the record's actual tier")

    def test_lock_sources_detects_tamper(self):
        r = run(self.root, "lock-sources")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(self.root, "lock-sources", "--verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        victim = self.root / "techniques" / "T-0001.json"
        orig = victim.read_text(encoding="utf-8")
        victim.write_text(orig.replace("SQL_EXEC", "SQL_EXEC "), encoding="utf-8")
        try:
            r = run(self.root, "lock-sources", "--verify")
            self.assertNotEqual(r.returncode, 0, "tampered record must fail manifest verification")
        finally:
            victim.write_text(orig, encoding="utf-8")

    def test_reindex_rebuilds(self):
        (self.root / "index.sqlite").unlink()
        r = run(self.root, "reindex")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(self.root, "find", "--effect", "EXEC", "--lang", "php")
        self.assertIn("T-0005", r.stdout)

    def test_promote_refuses_unproven(self):
        r = run(self.root, "promote", "T-0001")
        self.assertNotEqual(r.returncode, 0, "promote beyond provenance must be refused")

    def test_stale_outcome_not_penalized(self):
        # a fresh no_sink verdict penalises T-0001 below T-0002 on this profile
        run(self.root, "outcome", "T-0001", "--verdict", "no_sink",
            "--target-profile", "php8.2/laravel", "--oracle", "static")
        r = run(self.root, "find", "--effect", "SQL_EXEC", "--lang", "php",
                "--profile", "php8.2/laravel")
        ids = [l.split()[0] for l in r.stdout.splitlines() if l.startswith("T-")]
        self.assertGreater(ids.index("T-0001"), ids.index("T-0002"),
                           "penalised T-0001 must rank below the unpenalised T-0002")
        # bump the record to v2 (a fix): the v1 verdict must no longer poison ranking
        f = self.root / "techniques" / "T-0001.json"
        rec = json.loads(f.read_text(encoding="utf-8"))
        rec["record_version"] += 1
        f.write_text(json.dumps(rec), encoding="utf-8")
        self.assertEqual(run(self.root, "reindex").returncode, 0)
        r = run(self.root, "find", "--effect", "SQL_EXEC", "--lang", "php",
                "--profile", "php8.2/laravel")
        ids = [l.split()[0] for l in r.stdout.splitlines() if l.startswith("T-")]
        self.assertLess(ids.index("T-0001"), ids.index("T-0002"),
                        "stale (r1) verdict must not penalise the fixed r2 record")

    def test_auth_hard_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "graft"
            shutil.copytree(GRAFT, root, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock", "__pycache__"))
            cli = [sys.executable, str(root / "tools" / "tdb.py"), "--root", str(root)]
            subprocess.run(cli + ["init"], capture_output=True, check=True)
            # Phase-2 fixture: key + signed captures if present
            subprocess.run(cli + ["keygen", "--keyfile", str(Path(tmp) / "graft-signing.key")],
                           capture_output=True, check=True)
            for cap in sorted((root / "outcomes").glob("*.json")):
                if cap.name != "ledger.jsonl":
                    subprocess.run(cli + ["sign-capture", str(cap.relative_to(root))],
                                   capture_output=True, check=True)
            subprocess.run(cli + ["add"] + [str(p) for p in sorted((root / "techniques").glob("T-*.json"))],
                           capture_output=True, check=True)
            # no seed declares auth expr exactly 'none' -> the strict filter yields nothing
            r = run(root, "find", "--effect", "EXEC", "--lang", "php", "--auth", "none")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual([l for l in r.stdout.splitlines() if l.startswith("T-")], [])
            # a record declaring auth 'none' matches --auth none and is hidden under --auth user
            rec = json.loads((root / "techniques" / "T-0005.json").read_text(encoding="utf-8"))
            rec["id"] = "T-9007"
            rec["mechanism"][-1]["primitive"] = "LOOKUP"  # distinct mechanism
            rec["trust"] = "corroborated"
            # this test exercises the AUTH filter, not evidence mechanics — normalize the
            # clone's evidence so the binding gate doesn't (correctly) refuse a borrowed capture
            rec["evidence"] = {"status": "external_reported", "gate": "external_oracle",
                               "runs": [], "target": "corpus"}
            for pre in rec["preconditions"]:
                if pre["kind"] == "auth":
                    pre["expr"] = "none"
            (root / "techniques" / "T-9007.json").write_text(json.dumps(rec), encoding="utf-8")
            self.assertEqual(run(root, "add", str(root / "techniques" / "T-9007.json")).returncode, 0)
            r = run(root, "find", "--effect", "EXEC", "--lang", "php", "--auth", "none")
            self.assertIn("T-9007", r.stdout)
            r = run(root, "find", "--effect", "EXEC", "--lang", "php", "--auth", "user")
            self.assertNotIn("T-9007", r.stdout)

if __name__ == "__main__":
    unittest.main()