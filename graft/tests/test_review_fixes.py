# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Fixes for the 12 findings from the initial GRAFT security review.
Every test here was red against the pre-fix tree and encodes the review's demonstrated claim."""
import contextlib, importlib.util, json, shutil, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdb_fix", GRAFT / "tools" / "tdb.py")
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
    # Phase-2 fixture: tmp stores get their own signing key; real captures are signed.
    key = Path(tmpdir) / "graft-signing.key"
    assert run(root, "keygen", "--keyfile", str(key)).returncode == 0
    for cap in sorted((root / "outcomes").glob("*.json")):
        if cap.name != "ledger.jsonl":
            assert run(root, "sign-capture", str(cap.relative_to(root))).returncode == 0
    return root


def plant_donor_capture(root, tid="T-0001", name="donor-capture.json"):
    cap_rel = f"outcomes/{name}"
    (root / cap_rel).write_text(json.dumps({"probes": [{"technique": tid, "verdict": "confirmed"}]}),
                                 encoding="utf-8")
    assert run(root, "sign-capture", cap_rel).returncode == 0
    return cap_rel


def seed_db(root):
    r = run(root, "add", *[str(p) for p in sorted((root / "techniques").glob("T-*.json"))])
    assert r.returncode == 0, r.stderr
    return r


def load(tid, root):
    return json.loads((root / "techniques" / f"{tid}.json").read_text(encoding="utf-8"))


def write(rec, root):
    (root / "techniques" / f"{rec['id']}.json").write_text(json.dumps(rec), encoding="utf-8")


class TestGateSymmetry(unittest.TestCase):  # F-1
    def test_reindex_refuses_poison_and_keeps_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            cap_rel = plant_donor_capture(root, tid="T-0001")
            rec = load("T-0002", root)
            rec["id"] = "T-9001"; rec["trust"] = "locally-verified"
            rec["mechanism"][-1]["primitive"] = "COMPARE"
            rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                               "runs": [cap_rel], "target": "lab"}
            write(rec, root)
            r = run(root, "reindex")
            self.assertNotEqual(r.returncode, 0, "reindex must refuse gate violations")
            self.assertIn("T-9001", r.stdout + r.stderr)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                self.assertIsNone(db.execute("SELECT 1 FROM tech WHERE id='T-9001'").fetchone(),
                                  "poison must not reach the index")
                self.assertIsNotNone(db.execute("SELECT 1 FROM tech WHERE id='T-0001'").fetchone(),
                                     "clean records must still index")

    def test_promote_refuses_unknown_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            r = run(root, "promote", "T-9999", "--to", "locally-verified")
            self.assertNotEqual(r.returncode, 0, "promote must not operate on ids absent from the DB")
            self.assertIn("index", (r.stdout + r.stderr).lower())
            self.assertFalse((root / "techniques" / "T-9999.json").exists(),
                             "promote must never materialize an unadmitted record file")

    def test_promote_refuses_borrowed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            cap_rel = plant_donor_capture(root, tid="T-0001")
            rec = load("T-0002", root)
            rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                               "runs": [cap_rel], "target": "lab"}
            write(rec, root)
            r = run(root, "promote", "T-0002", "--to", "locally-verified")
            self.assertNotEqual(r.returncode, 0, "promote must run the binding gate")
            self.assertIn("bound", (r.stdout + r.stderr))

    def test_stats_reports_gate_violations_from_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            cap_rel = plant_donor_capture(root, tid="T-0001")
            rec = load("T-0002", root)
            rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                               "runs": [cap_rel], "target": "lab"}
            rec["trust"] = "locally-verified"
            write(rec, root)
            r = run(root, "stats")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("violation", r.stdout.lower())
            self.assertIn("T-0002", r.stdout)


class TestTrustCaps(unittest.TestCase):  # F-3 + F-2
    def test_empty_preconditions_caps_at_single_source(self):
        rec = load("T-0001", GRAFT)
        rec["preconditions"] = []
        self.assertEqual(tdb.admissible_trust(rec, GRAFT), "single-source")

    def test_all_manual_with_real_evidence_caps_at_single_source(self):
        rec = load("T-0001", GRAFT)
        for pre in rec["preconditions"]:
            if pre["kind"] in ("runtime", "dependency", "reachability", "input"):
                pre["check"] = {"kind": "manual", "spec": "eyeball it"}
        self.assertEqual(tdb.admissible_trust(rec, GRAFT), "single-source",
                         "the manual cap must be evaluated independent of evidence")

    def test_selfauthored_json_evidence_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            (root / "outcomes" / "selfauth.json").write_text(json.dumps({"captured": "trust me"}), encoding="utf-8")
            rec = load("T-0002", root)
            rec["id"] = "T-9002"; rec["trust"] = "locally-verified"
            rec["mechanism"][-1]["primitive"] = "COMPARE"
            rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                               "runs": ["outcomes/selfauth.json"], "target": "lab"}
            write(rec, root)
            r = run(root, "add", str(root / "techniques" / "T-9002.json"))
            self.assertNotEqual(r.returncode, 0, "non-probes-shaped evidence must be refused")
            self.assertIn("probes", (r.stdout + r.stderr))


class TestManifestScope(unittest.TestCase):  # F-5
    def test_ledger_tamper_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            self.assertEqual(run(root, "outcome", "T-0003", "--verdict", "no_sink",
                                 "--target-profile", "node/express").returncode, 0)
            self.assertEqual(run(root, "lock-sources").returncode, 0)
            led = root / "outcomes" / "ledger.jsonl"
            rows = [json.loads(l) for l in led.read_text(encoding="utf-8").splitlines() if l]
            for row in rows:
                if row["tech"] == "T-0003" and row["verdict"] == "no_sink":
                    row["verdict"] = "confirmed"
            led.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            r = run(root, "lock-sources", "--verify")
            self.assertNotEqual(r.returncode, 0, "ledger is the ranking source of truth — flips must fail the manifest")
            self.assertIn("ledger", (r.stdout + r.stderr))


class TestTtl(unittest.TestCase):  # F-4
    def test_overdue_flagged_in_find_and_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            db = sqlite3.connect(root / "index.sqlite")
            db.execute("UPDATE tech SET updated='2020-01-01T00:00:00Z' WHERE id='T-0002'")
            db.commit(); db.close()
            r = run(root, "find", "--effect", "SQL_EXEC", "--lang", "node")
            self.assertEqual(r.returncode, 0, r.stderr)
            line = [l for l in r.stdout.splitlines() if l.startswith("T-0002")]
            self.assertTrue(line)
            self.assertIn("TTL OVERDUE", line[0])
            r = run(root, "stats")
            self.assertIn("overdue", r.stdout.lower())


class TestFtsStar(unittest.TestCase):  # F-10
    def test_sanitize_star_prefix(self):
        self.assertEqual(tdb.sanitize_match("comm*"), '"comm"*')
        self.assertEqual(tdb.sanitize_match("unserialize cookie"), '"unserialize" "cookie"')

    def test_star_matches_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            r = run(root, "find", "--effect", "EXEC", "--fts", "comm*")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue([l for l in r.stdout.splitlines() if l.startswith("T-")],
                            "comm* must prefix-match 'command injection' in the corpus")


class TestContainment(unittest.TestCase):  # F-8
    def test_provenance_outside_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            outside = Path(tmp) / "outside.txt"
            outside.write_text("staged outside the root\n", encoding="utf-8")
            import hashlib
            rec = load("T-0002", root)
            rec["id"] = "T-9004"; rec["trust"] = "corroborated"
            rec["mechanism"][-1]["primitive"] = "COMPARE"
            rec["provenance"] = [
                {"src": "outside artifact", "author": "Someone", "path": "../outside.txt",
                 "sha256": hashlib.sha256(outside.read_bytes()).hexdigest()}]
            write(rec, root)
            r = run(root, "add", str(root / "techniques" / "T-9004.json"))
            self.assertNotEqual(r.returncode, 0, "provenance must be pinned inside the root")
            self.assertIn("root", (r.stdout + r.stderr))

    def test_probe_path_outside_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            outside = Path(tmp) / "outside-probe.json"
            outside.write_text("{}", encoding="utf-8")
            rec = load("T-0002", root)
            rec["id"] = "T-9005"; rec["trust"] = "corroborated"
            rec["mechanism"][-1]["primitive"] = "LOOKUP"
            rec["probes"] = [{"kind": "grep", "path": "../outside-probe.json"}]
            write(rec, root)
            r = run(root, "add", str(root / "techniques" / "T-9005.json"))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("root", (r.stdout + r.stderr))

    def test_evidence_runs_escape_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            outside = Path(tmp) / "outside-cap.json"
            outside.write_text("{}", encoding="utf-8")
            rec = load("T-0002", root)
            rec["id"] = "T-9006"; rec["trust"] = "locally-verified"
            rec["mechanism"][-1]["primitive"] = "COMPARE"
            rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                               "runs": ["../outside-cap.json"], "target": "lab"}
            write(rec, root)
            r = run(root, "add", str(root / "techniques" / "T-9006.json"))
            self.assertNotEqual(r.returncode, 0, "evidence runs must not escape the root")
            self.assertIn("root", (r.stdout + r.stderr))


class TestCleanErrors(unittest.TestCase):  # F-9
    def test_cost_min_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            r = run(root, "outcome", "T-0001", "--verdict", "no_sink",
                    "--target-profile", "php/x", "--cost-min", "abc")
            self.assertEqual(r.returncode, 2)
            self.assertNotIn("Traceback", r.stdout + r.stderr)
            self.assertIn("cost", (r.stdout + r.stderr).lower())

    def test_slots_json_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            seed_db(root)
            r = run(root, "outcome", "T-0001", "--verdict", "no_sink",
                    "--target-profile", "php/x", "--slots-json", "{bad")
            self.assertEqual(r.returncode, 2)
            self.assertNotIn("Traceback", r.stdout + r.stderr)

    def test_string_confidence_clean_validation_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            rec = load("T-0002", root)
            rec["id"] = "T-9007"; rec["trust"] = "corroborated"
            rec["mechanism"][-1]["primitive"] = "LOOKUP"
            rec["confidence"] = {"curator": "high"}
            write(rec, root)
            r = run(root, "add", str(root / "techniques" / "T-9007.json"))
            self.assertEqual(r.returncode, 2)
            self.assertNotIn("Traceback", r.stdout + r.stderr)
            self.assertIn("confidence", (r.stdout + r.stderr).lower())

    def test_adapt_bad_pattern_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            fam = root / "vocab" / "equivalents" / "sink.exec.shell.json"
            data = json.loads(fam.read_text(encoding="utf-8"))
            data["cells"]["php"]["patterns"] = ["("]
            fam.write_text(json.dumps(data), encoding="utf-8")
            target = Path(tmp) / "src"; target.mkdir()
            (target / "a.php").write_text("<?php system($_GET['x']); ?>\n", encoding="utf-8")
            r = run(root, "adapt", "T-0005", "--target", str(target), "--lang", "php")
            self.assertEqual(r.returncode, 2, (r.stdout + r.stderr)[:400])
            self.assertNotIn("Traceback", r.stdout + r.stderr)
            self.assertIn("pattern", (r.stdout + r.stderr).lower())


class TestBatchAndPaths(unittest.TestCase):  # F-11
    def test_add_batch_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            cap_rel = plant_donor_capture(root, tid="T-0001")
            good1 = load("T-0002", root); good1["id"] = "T-9010"
            good1["mechanism"][-1]["primitive"] = "COMPARE"; good1["trust"] = "corroborated"
            good2 = load("T-0003", root); good2["id"] = "T-9011"
            good2["mechanism"][-1]["primitive"] = "LOOKUP"; good2["trust"] = "corroborated"
            poison = load("T-0002", root); poison["id"] = "T-9012"
            poison["mechanism"][-1]["primitive"] = "INVOKE"; poison["trust"] = "locally-verified"
            poison["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                                  "runs": [cap_rel], "target": "lab"}
            for rec in (good1, good2, poison):
                write(rec, root)
            r = run(root, "add", *[str(root / "techniques" / f"{r['id']}.json") for r in (good1, good2, poison)])
            self.assertNotEqual(r.returncode, 0, "a poison anywhere in the batch must fail the batch")
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                for rid in ("T-9010", "T-9011", "T-9012"):
                    self.assertIsNone(db.execute("SELECT 1 FROM tech WHERE id=?", (rid,)).fetchone(),
                                       f"{rid} must not be admitted")

    def test_verify_table_requires_tests_equiv_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            shutil.copy(GRAFT / "tests" / "equiv" / "php_exec_shell.php", root / "evil.php")
            fam = root / "vocab" / "equivalents" / "sink.eval.json"
            data = json.loads(fam.read_text(encoding="utf-8"))
            data["cells"]["php"]["verified"] = {"how": "executed", "test": "evil.php", "date": "2026-11-20"}
            fam.write_text(json.dumps(data), encoding="utf-8")
            r = run(root, "verify-table")
            self.assertNotEqual(r.returncode, 0, "executed cells must declare tests under tests/equiv/")
            self.assertIn("tests/equiv", r.stdout + r.stderr)


class TestAdaptExperiments(unittest.TestCase):  # F-12
    def test_one_experiment_per_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            target = Path(tmp) / "src"; target.mkdir()
            (target / "q.php").write_text(
                "<?php $id = $_GET['id']; $q = \"SELECT * FROM t WHERE x = '$id'\";"
                "mysqli_query($link, $q); ?>\n", encoding="utf-8")
            r = run(root, "adapt", "T-0001", "--target", str(target), "--lang", "php")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("one experiment per unknown", r.stdout)
            self.assertIn("[static]", r.stdout, "reachability unknowns map to the static oracle first")


if __name__ == "__main__":
    unittest.main()