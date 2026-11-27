# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Distillation pipeline: stage -> draft -> checklist; admission stays behind the gate."""
import hashlib, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent


def run(root, *args):
    return subprocess.run([sys.executable, str(Path(root) / "tools" / "tdb.py"),
                           "--root", str(root), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


class TestDistill(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "graft"
        shutil.copytree(GRAFT, self.root, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock", "__pycache__"))
        self.art = Path(self.tmp.name) / "advisory.txt"
        self.art.write_text("ADVISORY: a mechanism description worth distilling.\n", encoding="utf-8")
        assert run(self.root, "init").returncode == 0
        # Phase-2 fixture: key + signed real captures for this tmp store
        assert run(self.root, "keygen", "--keyfile",
                   str(Path(self.tmp.name) / "graft-signing.key")).returncode == 0
        for cap in sorted((self.root / "outcomes").glob("*.json")):
            if cap.name != "ledger.jsonl":
                assert run(self.root, "sign-capture", str(cap.relative_to(self.root))).returncode == 0
        assert run(self.root, "add", *[str(p) for p in
                                       sorted((self.root / "techniques").glob("T-*.json"))]).returncode == 0

    def tearDown(self):
        self.tmp.cleanup()

    def test_distill_stages_and_drafts(self):
        r = run(self.root, "distill", "--from", str(self.art),
                "--author", "Test Author", "--title", "Test draft technique")
        self.assertEqual(r.returncode, 0, r.stderr)
        drafts = list((self.root / "drafts").glob("T-*.draft.json"))
        self.assertEqual(len(drafts), 1)
        draft = json.loads(drafts[0].read_text(encoding="utf-8"))
        nums = [int(p.stem.split("-")[1]) for p in (self.root / "techniques").glob("T-*.json")]
        self.assertEqual(draft["id"], f"T-{max(nums) + 1:04d}",
                         "next free id after the admitted corpus")
        staged = self.root / draft["provenance"][0]["src"]
        self.assertTrue(staged.exists(), "artifact must be staged under sources/")
        self.assertEqual(draft["provenance"][0]["author"], "Test Author")
        self.assertEqual(draft["provenance"][0]["sha256"],
                         hashlib.sha256(self.art.read_bytes()).hexdigest())
        self.assertIn("checklist", r.stdout.lower())
        self.assertIn("incomplete", r.stdout.lower())

    def test_distill_refuses_duplicate_source(self):
        self.assertEqual(run(self.root, "distill", "--from", str(self.art),
                             "--author", "A", "--title", "T1").returncode, 0)
        r = run(self.root, "distill", "--from", str(self.art), "--author", "A", "--title", "T2")
        self.assertNotEqual(r.returncode, 0, "same artifact must not be distilled twice")
        self.assertIn("already staged", (r.stdout + r.stderr).lower())

    def test_raw_draft_cannot_admit(self):
        r = run(self.root, "distill", "--from", str(self.art), "--author", "A", "--title", "T")
        self.assertEqual(r.returncode, 0, r.stderr)
        draft_path = next((self.root / "drafts").glob("T-*.draft.json"))
        r = run(self.root, "add", str(draft_path))
        self.assertNotEqual(r.returncode, 0, "an incomplete draft must be refused by the gate")

    def test_completed_draft_admits_through_gate(self):
        self.assertEqual(run(self.root, "distill", "--from", str(self.art),
                             "--author", "Curator", "--title", "T").returncode, 0)
        draft_path = next((self.root / "drafts").glob("T-*.draft.json"))
        draft = json.loads(draft_path.read_text(encoding="utf-8"))
        seed = json.loads((self.root / "techniques" / "T-0002.json").read_text(encoding="utf-8"))
        seed["id"] = draft["id"]
        seed["mechanism"][-1]["primitive"] = "LOOKUP"  # distinct mechanism
        seed["title"] = "Distilled from a staged advisory"
        seed["provenance"] = draft["provenance"] + [
            {"src": "MITRE CWE-89", "author": "MITRE", "corroborates": "mechanism class"}]
        seed["trust"] = "corroborated"
        moved = self.root / "techniques" / f"{draft['id']}.json"
        moved.write_text(json.dumps(seed), encoding="utf-8")
        r = run(self.root, "add", str(moved))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"added {draft['id']}", r.stdout)
        self.assertIn("corroborated", r.stdout)

    def test_distill_list(self):
        self.assertEqual(run(self.root, "distill", "--from", str(self.art),
                             "--author", "A", "--title", "T").returncode, 0)
        r = run(self.root, "distill", "--list")
        self.assertEqual(r.returncode, 0, r.stderr)
        nums = [int(p.stem.split("-")[1]) for p in (self.root / "techniques").glob("T-*.json")]
        self.assertIn(f"T-{max(nums) + 1:04d}", r.stdout)


if __name__ == "__main__":
    unittest.main()