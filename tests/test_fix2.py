# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Fixes for the six graft-full-review-2 findings (R2-1 text, R2-2, R2-3, R2-4, R2-5, R2-6).
Every test here was red against the pre-fix tree and encodes the review's demonstrated claim."""
import contextlib, importlib.util, json, re, shutil, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdb_fix2", GRAFT / "tools" / "tdb.py")
tdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tdb)


def run(root, *args):
    return subprocess.run([sys.executable, str(Path(root) / "tools" / "tdb.py"),
                           "--root", str(root), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def fresh(tmpdir):
    root = Path(tmpdir) / "graft"
    shutil.copytree(GRAFT, root, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock", "__pycache__"))
    assert run(root, "init").returncode == 0
    return root


def load(tid, root):
    return json.loads((root / "techniques" / f"{tid}.json").read_text(encoding="utf-8"))


def write(rec, root):
    (root / "techniques" / f"{rec['id']}.json").write_text(json.dumps(rec), encoding="utf-8")


class TestCanonCollision(unittest.TestCase):  # R2-2
    def test_fresh_db_add_refuses_to_overwrite_existing_canon_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            rec = load("T-0005", root)
            rec["title"] = "OVERWRITTEN BY FRESH-DB ADD"
            # corpus-level evidence: the canon-collision concern is orthogonal to
            # reproduced_local (Phase-2 signature gate would fire first otherwise)
            rec["evidence"] = {"status": "external_reported", "gate": "external_oracle",
                               "runs": [], "target": "corpus"}
            outside = Path(tmp) / "fake-T-0005.json"
            outside.write_text(json.dumps(rec), encoding="utf-8")
            before = (root / "techniques" / "T-0005.json").read_text(encoding="utf-8")
            r = run(root, "add", str(outside))
            self.assertNotEqual(r.returncode, 0, "fresh-DB add must not silently overwrite a canon file")
            self.assertIn("canon file", (r.stdout + r.stderr))
            self.assertEqual((root / "techniques" / "T-0005.json").read_text(encoding="utf-8"), before,
                             "the canon file must be byte-unchanged")

    def test_same_path_add_still_admits(self):
        # re-adding the store's own canon file is how seed paths work; it must keep working
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            r = run(root, "add", str(root / "techniques" / "T-0002.json"))
            self.assertEqual(r.returncode, 0, "adding the store's own file at its canon path is legal")


class TestOutcomeAdmission(unittest.TestCase):  # R2-4
    def _poisoned_root(self, tmp):
        root = fresh(tmp)
        cap_rel = "outcomes/donor-capture.json"
        (root / cap_rel).write_text(json.dumps({"probes": [{"technique": "T-0005", "verdict": "confirmed"}]}),
                                     encoding="utf-8")
        rec = load("T-0002", root)
        rec["id"] = "T-9102"; rec["trust"] = "locally-verified"
        rec["mechanism"][-1]["primitive"] = "COMPARE"
        rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                           "runs": [cap_rel], "target": "lab"}
        write(rec, root)   # planted in the store; reindex must refuse it
        r = run(root, "reindex")
        self.assertNotEqual(r.returncode, 0, "reindex must refuse the borrowed-evidence poison")
        return root

    def test_outcome_refused_for_gate_refused_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._poisoned_root(tmp)
            ledger_before = (root / "outcomes" / "ledger.jsonl").read_text(encoding="utf-8")
            r = run(root, "outcome", "T-9102", "--verdict", "confirmed", "--target-profile", "php/x")
            self.assertNotEqual(r.returncode, 0, "outcome must require an indexed record")
            self.assertIn("not in the index", (r.stdout + r.stderr))
            self.assertEqual((root / "outcomes" / "ledger.jsonl").read_text(encoding="utf-8"), ledger_before,
                             "no ledger row may be written for a gate-refused record")

    def test_outcome_still_works_for_admitted_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            assert run(root, "add", str(root / "techniques" / "T-0002.json")).returncode == 0
            r = run(root, "outcome", "T-0002", "--verdict", "confirmed", "--target-profile", "php/x")
            self.assertEqual(r.returncode, 0, "admitted records keep the outcome path")
            self.assertIn("outcome: T-0002", r.stdout)


class TestCleanErrors(unittest.TestCase):  # R2-5
    def test_list_record_json_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            bad = Path(tmp) / "listrec.json"
            bad.write_text("[1, 2, 3]", encoding="utf-8")
            r = run(root, "add", str(bad))
            self.assertEqual(r.returncode, 2, "non-dict record JSON must be a clean error")
            self.assertIn("JSON object", (r.stdout + r.stderr))
            self.assertNotIn("Traceback", r.stderr)

    def test_reindex_skips_non_dict_record_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            (root / "techniques" / "T-9999.json").write_text("[1, 2, 3]", encoding="utf-8")
            r = run(root, "reindex")
            self.assertNotEqual(r.returncode, 0, "a non-dict file in the store must fail reindex")
            self.assertIn("T-9999", (r.stdout + r.stderr))
            self.assertNotIn("Traceback", r.stderr)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                n = db.execute("SELECT count(*) FROM tech WHERE id='T-9999'").fetchone()[0]
            self.assertEqual(n, 0, "the non-dict file must not be indexed")

    def test_distill_directory_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            r = run(root, "distill", "--from", tmp, "--author", "x", "--title", "y")
            self.assertEqual(r.returncode, 2, "distill from a directory must be a clean error")
            self.assertIn("regular file", (r.stdout + r.stderr))
            self.assertNotIn("Traceback", r.stderr)


class TestTtlDedupe(unittest.TestCase):  # R2-6
    def test_ttl_overdue_defined_once(self):
        src = (GRAFT / "tools" / "tdb.py").read_text(encoding="utf-8")
        self.assertEqual(src.count("def ttl_overdue("), 1,
                         "the duplicate ttl_overdue definition must be removed")

    def test_ttl_behavior_unchanged(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        old = (now - datetime.timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
        new = (now - datetime.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertTrue(tdb.ttl_overdue({"ttl_days": 365}, old))
        self.assertFalse(tdb.ttl_overdue({"ttl_days": 365}, new))


class TestManifestCodeScope(unittest.TestCase):  # R2-3
    def _locked_root(self, tmp):
        root = fresh(tmp)
        assert run(root, "lock-sources").returncode == 0
        return root

    def test_tampered_tdb_py_fails_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._locked_root(tmp)
            p = root / "tools" / "tdb.py"
            p.write_text(p.read_text(encoding="utf-8") + "\n# EVIL\n", encoding="utf-8")
            r = run(root, "lock-sources", "--verify")
            self.assertNotEqual(r.returncode, 0, "a tampered gate must fail the manifest")
            self.assertIn("tools/tdb.py", r.stderr)

    def test_tampered_unit_test_fails_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._locked_root(tmp)
            p = root / "tests" / "test_tdb.py"
            p.write_text(p.read_text(encoding="utf-8") + "\n# EVIL\n", encoding="utf-8")
            r = run(root, "lock-sources", "--verify")
            self.assertNotEqual(r.returncode, 0, "a tampered unit test must fail the manifest")

    def test_tampered_readme_fails_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._locked_root(tmp)
            p = root / "README.md"
            p.write_text(p.read_text(encoding="utf-8") + "\nEVIL\n", encoding="utf-8")
            r = run(root, "lock-sources", "--verify")
            self.assertNotEqual(r.returncode, 0, "a tampered README must fail the manifest")

    def test_untampered_tree_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._locked_root(tmp)
            r = run(root, "lock-sources", "--verify")
            self.assertEqual(r.returncode, 0)
            m = re.search(r"verified: (\d+) files match", r.stdout)
            self.assertTrue(m and int(m.group(1)) > 69,
                            "count must exceed the old 69 (knowledge-only) — code is "
                            "now in scope; the store may grow (T-0014-era files pushed "
                            "it past the 80s decade this test originally pinned)")

    def test_manifest_covers_code_and_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._locked_root(tmp)
            assert run(root, "lock-sources").returncode == 0
            manifest = json.loads((root / "sources.lock").read_text(encoding="utf-8"))["files"]
            for needed in ("tools/tdb.py", "tests/test_tdb.py", "tests/test_fix2.py",
                           "README.md", "skills/graft/SKILL.md", ".agents/skills/graft/SKILL.md",
                           "LICENSE", "NOTICE", "SECURITY.md", "plugin.json", "pyproject.toml"):
                self.assertIn(needed, manifest, f"manifest must cover {needed}")
            self.assertNotIn("drafts", " ".join(manifest), "drafts stay unstaged by design")


class TestBindingDocstringHonesty(unittest.TestCase):  # R2-1 (text only)
    def test_docstring_states_the_limit(self):
        src = (GRAFT / "tools" / "tdb.py").read_text(encoding="utf-8")
        self.assertIn("Phase-2", src,
                      "the binding gate's docstring must name capture authenticity as the Phase-2 gap")


if __name__ == "__main__":
    unittest.main()