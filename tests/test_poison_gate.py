# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Poison gate: same-author 'corroboration', fake local repro, hash mismatch, dup mechanism."""
import importlib.util, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdb", GRAFT / "tools" / "tdb.py")
tdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tdb)

BASE = json.loads((GRAFT / "techniques" / "T-0001.json").read_text(encoding="utf-8"))
# Poison-mechanics fixtures must NOT inherit T-0001's live evidence state: a record with
# reproduced_local evidence + existing runs legitimately outranks provenance rules, so the
# same-author/manual-cap tests would test nothing. Normalize to corpus-level evidence.
BASE["evidence"] = {"status": "external_reported", "gate": "external_oracle", "runs": [], "target": "corpus"}

def tmp_graft(tmpdir):
    dst = Path(tmpdir) / "graft"
    shutil.copytree(GRAFT, dst, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock", "__pycache__"))
    return dst

class TestPoisonGate(unittest.TestCase):
    def test_same_author_is_single_source(self):
        rec = json.loads(json.dumps(BASE))
        rec["id"] = "T-9001"
        rec["provenance"] = [
            {"src": "mirror-A.example/writeup", "author": "Attacker Syndication", "corroborates": "x"},
            {"src": "mirror-B.example/copy", "author": "Attacker Syndication", "corroborates": "x"},
        ]
        rec["trust"] = "corroborated"
        self.assertEqual(tdb.admissible_trust(rec, GRAFT), "single-source")

    def test_fake_local_repro_refused(self):
        rec = json.loads(json.dumps(BASE))
        rec["id"] = "T-9002"
        rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                            "runs": ["outcomes/never-written.json"], "target": "lab"}
        rec["trust"] = "locally-verified"
        errs = tdb.validate_record(rec, GRAFT, tdb.load_vocab(GRAFT))
        self.assertTrue(any("evidence" in e for e in errs), errs)

    def test_manual_check_caps_trust(self):
        rec = json.loads(json.dumps(BASE))
        rec["id"] = "T-9003"
        rec["preconditions"][1]["check"] = {"kind": "manual", "spec": "eyeball it"}
        self.assertEqual(tdb.admissible_trust(rec, GRAFT), "single-source")

    def test_hash_mismatch_refused_at_add(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = tmp_graft(tmp)
            rec = json.loads(json.dumps(BASE))
            rec["id"] = "T-9004"
            rec["mechanism"] = [
                {"n": 1, "does": "x", "primitive": "UNTRUSTED_INPUT"},
                {"n": 2, "does": "y", "primitive": "WRITE"},
                {"n": 3, "does": "z", "primitive": "READ"},
                {"n": 4, "does": "w", "primitive": "EXEC"},
            ]
            rec["provenance"] = [
                {"src": "local artifact", "author": "Someone", "path": "techniques/T-0001.json",
                 "sha256": "0" * 64},
            ]
            (root / "techniques" / "T-9004.json").write_text(json.dumps(rec), encoding="utf-8")
            r = subprocess.run([sys.executable, str(root / "tools" / "tdb.py"), "--root", str(root),
                                "add", str(root / "techniques" / "T-9004.json")],
                               capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("provenance", (r.stdout + r.stderr).lower())

    def test_duplicate_mechanism_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = tmp_graft(tmp)
            cli = [sys.executable, str(root / "tools" / "tdb.py"), "--root", str(root)]
            subprocess.run(cli + ["init"], capture_output=True, check=True)
            # Phase-2 fixture: key + signed real captures for this tmp store
            subprocess.run(cli + ["keygen", "--keyfile", str(Path(tmp) / "graft-signing.key")],
                           capture_output=True, check=True)
            for cap in sorted((root / "outcomes").glob("*.json")):
                if cap.name != "ledger.jsonl":
                    subprocess.run(cli + ["sign-capture", str(cap.relative_to(root))],
                                   capture_output=True, check=True)
            add = subprocess.run(cli + ["add"] + [str(p) for p in sorted((root / "techniques").glob("T-*.json"))],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(add.returncode, 0, add.stderr)
            rec = json.loads(json.dumps(BASE))
            rec["id"] = "T-9005"  # same effect + primitive chain + sink family as T-0001
            victim = root / "techniques" / "T-9005.json"
            victim.write_text(json.dumps(rec), encoding="utf-8")
            r = subprocess.run(cli + ["add", str(victim)], capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
            self.assertNotEqual(r.returncode, 0, "duplicate mechanism must be refused")
            self.assertIn("mech", (r.stdout + r.stderr).lower())

    def test_quarantine_exclusion_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = tmp_graft(tmp)
            rec = json.loads(json.dumps(BASE))
            rec["id"] = "T-9006"
            rec["title"] = "Same-author poisoned SQLi clone"
            rec["mechanism"][-1]["primitive"] = "COMPARE"  # distinct mechanism: exercises the trust gate, not the dedupe gate
            rec["provenance"] = [
                {"src": "a.example/w", "author": "One Author", "corroborates": "x"},
                {"src": "b.example/copy", "author": "One Author", "corroborates": "x"},
            ]
            rec["trust"] = "corroborated"
            (root / "techniques" / "T-9006.json").write_text(json.dumps(rec), encoding="utf-8")
            cli = [sys.executable, str(root / "tools" / "tdb.py"), "--root", str(root)]
            subprocess.run(cli + ["init"], capture_output=True, check=True)
            # Phase-2 fixture: key + signed real captures for this tmp store
            subprocess.run(cli + ["keygen", "--keyfile", str(Path(tmp) / "graft-signing.key")],
                           capture_output=True, check=True)
            for cap in sorted((root / "outcomes").glob("*.json")):
                if cap.name != "ledger.jsonl":
                    subprocess.run(cli + ["sign-capture", str(cap.relative_to(root))],
                                   capture_output=True, check=True)
            add = subprocess.run(cli + ["add"] + [str(p) for p in sorted((root / "techniques").glob("T-*.json"))],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(add.returncode, 0, add.stderr)
            self.assertIn("downgrad", add.stdout.lower(), "same-author record must be loudly downgraded")
            find = subprocess.run(cli + ["find", "--effect", "SQL_EXEC", "--lang", "php"],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertNotIn("T-9006", find.stdout, "quarantined record must be excluded")
            find2 = subprocess.run(cli + ["find", "--effect", "SQL_EXEC", "--lang", "php",
                                          "--include-quarantined"], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace")
            self.assertIn("T-9006", find2.stdout)

    def test_borrowed_evidence_refused(self):
        """Phase-1 live poison finding: a clone must not ride on another record's evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "graft"
            shutil.copytree(GRAFT, root, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock", "__pycache__"))
            cli = [sys.executable, str(root / "tools" / "tdb.py"), "--root", str(root)]
            subprocess.run(cli + ["init"], capture_output=True, check=True)
            ev = root / "outcomes" / "lab-capture.json"
            ev.write_text(json.dumps({"probes": [{"technique": "T-0001", "verdict": "confirmed"}]}), encoding="utf-8")
            rec = json.loads((root / "techniques" / "T-0005.json").read_text(encoding="utf-8"))
            rec["id"] = "T-9003"
            rec["mechanism"][-1]["primitive"] = "COMPARE"  # distinct mechanism
            rec["trust"] = "locally-verified"
            rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                               "runs": ["outcomes/lab-capture.json"], "target": "lab"}
            victim = root / "techniques" / "T-9003.json"
            victim.write_text(json.dumps(rec), encoding="utf-8")
            r = subprocess.run(cli + ["add", str(victim)], capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
            self.assertNotEqual(r.returncode, 0, "borrowed evidence must be refused")
            self.assertIn("bound", (r.stdout + r.stderr))

if __name__ == "__main__":
    unittest.main()