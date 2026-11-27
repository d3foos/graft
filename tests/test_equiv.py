# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Equivalence-table verification: every executed cell re-runs green; documented cells listed honestly."""
import importlib.util, json, subprocess, sys, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdb", GRAFT / "tools" / "tdb.py")
tdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tdb)

class TestEquivalents(unittest.TestCase):
    def test_verify_table_green(self):
        r = subprocess.run([sys.executable, str(GRAFT / "tools" / "tdb.py"),
                            "--root", str(GRAFT), "verify-table"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("executed cells", r.stdout)
        self.assertIn("0 failed", r.stdout)

    def test_documented_cells_disclosed(self):
        r = subprocess.run([sys.executable, str(GRAFT / "tools" / "tdb.py"),
                            "--root", str(GRAFT), "verify-table"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertIn("needs_local_verification", r.stdout)

    def test_no_dangling_test_refs(self):
        for fam_file in (GRAFT / "vocab" / "equivalents").glob("*.json"):
            fam = json.loads(fam_file.read_text(encoding="utf-8"))
            for cell in fam["cells"].values():
                v = cell.get("verified") or {}
                if v.get("how") == "executed":
                    self.assertTrue((GRAFT / v["test"]).exists(),
                                    f"{fam_file.name}: {v['test']} missing")

if __name__ == "__main__":
    unittest.main()