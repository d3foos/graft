# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Schema v4 invariants over the shipped vocab + corpus records."""
import importlib.util, json, re, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdb", GRAFT / "tools" / "tdb.py")
tdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tdb)

VOCAB = tdb.load_vocab(GRAFT)
RECORDS = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((GRAFT / "techniques").glob("T-*.json"))]

class TestVocab(unittest.TestCase):
    def test_effects_no_deserialize(self):
        self.assertNotIn("DESERIALIZE", VOCAB.effects)
        self.assertEqual(len(VOCAB.effects), 14)

    def test_slot_families_language_neutral(self):
        bad = [f for f in VOCAB.families if re.search(r"\.(php|py|python|js|node|java|rb|ruby|cs|csharp|go|rust)$", f)]
        self.assertEqual(bad, [], f"language-embedding families: {bad}")

class TestRecords(unittest.TestCase):
    def test_all_ten_validate(self):
        for rec in RECORDS:
            errs = tdb.validate_record(rec, GRAFT, VOCAB)
            self.assertEqual(errs, [], f"{rec['id']}: {errs}")

    def test_bypass_names_target(self):
        for rec in RECORDS:
            for step in rec["mechanism"]:
                if step["primitive"] == "BYPASS":
                    self.assertTrue(step.get("bypasses"), f"{rec['id']} BYPASS without bypasses")

    def test_langs_structured(self):
        for rec in RECORDS:
            self.assertIn(rec["langs"]["origin"], tdb.LANGS)
            for lang in rec["langs"]["transferable"]:
                self.assertIn(lang, tdb.LANGS)

    def test_corroborated_dual_author_no_manual(self):
        for rec in RECORDS:
            if rec["trust"] == "corroborated":
                authors = {p["author"] for p in rec["provenance"]}
                self.assertGreaterEqual(len(authors), 2, rec["id"])
                for pre in rec["preconditions"]:
                    chk = pre.get("check") or {}
                    if pre["kind"] in ("runtime", "dependency", "reachability", "input"):
                        self.assertNotEqual(chk.get("kind"), "manual", f"{rec['id']} manual instrumental check")

    def test_probe_paths_exist(self):
        for rec in RECORDS:
            for probe in rec["probes"]:
                self.assertTrue((GRAFT / probe["path"]).exists(), f"{rec['id']} -> {probe['path']}")

    def test_evidence_gate_enum(self):
        for rec in RECORDS:
            self.assertIn(rec["evidence"]["gate"], tdb.EVIDENCE_GATES, rec["id"])

    def test_combines_with_resolvable(self):
        ids = {rec["id"] for rec in RECORDS}
        for rec in RECORDS:
            for ref in rec["combines_with"]:
                self.assertIn(ref, ids, f"{rec['id']} -> {ref}")

    def test_equivalents_refs_exist(self):
        for rec in RECORDS:
            for slot in rec["slots"].values():
                ref = slot.get("equivalents")
                if ref:
                    self.assertTrue((GRAFT / ref).exists(), f"{rec['id']} -> {ref}")

    def test_same_effect_refs_exist_and_align(self):
        """transfer.same_effect must be an existing vocab/equivalents path that names one of
        the record's own slot families. The field was previously unvalidated, which let
        dangling and copy-pasted pointers in (see graft-records-*-review.md)."""
        for rec in RECORDS:
            fams = set(rec["slots"].keys())
            for ref in (rec.get("transfer") or {}).get("same_effect") or []:
                self.assertTrue(
                    str(ref).startswith("vocab/equivalents/"),
                    f"{rec['id']} same_effect must be a vocab/equivalents/ path: {ref}")
                self.assertTrue((GRAFT / ref).exists(),
                                f"{rec['id']} same_effect references missing file: {ref}")
                fam = ref.split("/")[-1][:-5]
                self.assertIn(fam, fams,
                              f"{rec['id']} same_effect {fam} is not one of its own slot families")

if __name__ == "__main__":
    unittest.main()