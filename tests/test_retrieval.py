# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Retrieval invariants: profile similarity, FTS sanitization, ranking penalties."""
import importlib.util, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdb", GRAFT / "tools" / "tdb.py")
tdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tdb)

class TestProfileSimilar(unittest.TestCase):
    def test_same_lang_framework(self):
        self.assertTrue(tdb.profile_similar("php8.2/laravel", "php8.3/laravel"))

    def test_cross_lang(self):
        self.assertFalse(tdb.profile_similar("php8.2/laravel", "node/express"))

    def test_unspecified_framework_matches_lang(self):
        self.assertTrue(tdb.profile_similar("php", "php8.2/laravel"))
        self.assertFalse(tdb.profile_similar("php", "node/express"))

class TestFtsSanitize(unittest.TestCase):
    def test_hostile_query_neutralized(self):
        s = tdb.sanitize_match('"; DROP TABLE tech; --')
        toks = s.split()
        self.assertTrue(toks)
        for t in toks:
            self.assertRegex(t, r'^"[A-Za-z0-9_*]+"$', t)  # quoted word-chars only; no operators, parens, or raw quotes survive

    def test_plain_terms_quoted(self):
        self.assertEqual(tdb.sanitize_match("unserialize cookie"), '"unserialize" "cookie"')

class TestRanking(unittest.TestCase):
    def test_fail_penalty_wins_over_neutral(self):
        # a record with no negative outcomes on this profile outranks one that keeps dying here
        a = tdb.rank_terms(rec_trust="corroborated", transfer_history=0.0,
                           fail_penalty=0.0, fts=1.0, tag=0.5)
        b = tdb.rank_terms(rec_trust="corroborated", transfer_history=0.0,
                           fail_penalty=2.0, fts=1.0, tag=0.5)
        self.assertGreater(a, b)

    def test_transfer_history_helps(self):
        a = tdb.rank_terms(rec_trust="corroborated", transfer_history=1.0,
                           fail_penalty=0.0, fts=0.0, tag=0.0)
        b = tdb.rank_terms(rec_trust="corroborated", transfer_history=-0.5,
                           fail_penalty=0.0, fts=0.0, tag=0.0)
        self.assertGreater(a, b)

if __name__ == "__main__":
    unittest.main()