# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Fixes for the graft-full-review-3 findings (R3-1..R3-4). Red on the baseline tree:
the malformed-.sig and bad-keyfile probes CRASH the gates (exit 1, traceback, reindex
aborts at an empty index); a missing ed25519.py bricks every command; CLI runs drop
bytecode residue into the store."""
import contextlib, hashlib, importlib.util, json, os, shutil, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent


def run(root, *args):
    return subprocess.run([sys.executable, str(Path(root) / "tools" / "tdb.py"),
                           "--root", str(root), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def fresh(tmpdir):
    root = Path(tmpdir) / "graft"
    shutil.copytree(GRAFT, root, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock",
                                                               "__pycache__"))
    assert run(root, "init").returncode == 0
    key = Path(tmpdir) / "graft-signing.key"
    assert run(root, "keygen", "--keyfile", str(key)).returncode == 0
    for cap in sorted((root / "outcomes").glob("*.json")):
        if cap.name != "ledger.jsonl":
            assert run(root, "sign-capture", str(cap.relative_to(root))).returncode == 0
    return root


def key_for(root):
    return Path(root).parent / (Path(root).name + "-signing.key")


def plant(root, tid="T-9205", cap_name="cap.json", sig=None):
    """A record citing cap_name with a fully-attacking .sig: correct key_id AND
    correct msg_sha256 (both attacker-computable) — whatever `sig` provides."""
    k = json.loads(key_for(root).read_text(encoding="utf-8"))
    rec = json.loads((root / "techniques" / "T-0002.json").read_text(encoding="utf-8"))
    rec["id"] = tid; rec["trust"] = "locally-verified"
    rec["mechanism"][-1]["primitive"] = "COMPARE"
    (root / "outcomes" / cap_name).write_text(json.dumps(
        {"probes": [{"technique": tid, "verdict": "confirmed"}]}), encoding="utf-8")
    rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                       "runs": [f"outcomes/{cap_name}"], "target": "lab"}
    (root / "techniques" / f"{tid}.json").write_text(json.dumps(rec), encoding="utf-8")
    sha = hashlib.sha256((root / "outcomes" / cap_name).read_bytes()).hexdigest()
    body = {"alg": "ed25519", "key_id": k["key_id"], "msg_sha256": sha}
    body.update(sig or {})
    (root / "outcomes" / (cap_name + ".sig")).write_text(json.dumps(body), encoding="utf-8")
    return root / "techniques" / f"{tid}.json"


class TestMalformedSig(unittest.TestCase):  # R3-1
    def _assert_clean_refusal(self, r):
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_nonhex_sig_refused_cleanly_and_reindex_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            victim = plant(root, sig={"sig": "zz-not-hex"})
            self._assert_clean_refusal(run(root, "add", str(victim)))
            # the headline: reindex must SURVIVE the planted file and index the rest
            r = run(root, "reindex")
            self.assertNotEqual(r.returncode, 0, "the malformed record must still be refused")
            self.assertNotIn("Traceback", r.stderr)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                n = dict(db.execute("SELECT id, trust FROM tech").fetchall())
            self.assertIn("T-0001", n, "clean records must still be indexed")
            self.assertNotIn("T-9205", n)
            out = run(root, "stats").stdout + run(root, "stats").stderr
            self.assertIn("malformed", out, "stats must flag the malformed .sig from the files")

    def test_nondict_sig_refused_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            victim = plant(root)
            (root / "outcomes" / "cap.json.sig").write_text("[1, 2]", encoding="utf-8")
            self._assert_clean_refusal(run(root, "add", str(victim)))
            r = run(root, "reindex")
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("Traceback", r.stderr)

    def test_wrong_length_sig_refused_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            victim = plant(root, sig={"sig": "ab" * 63})
            self._assert_clean_refusal(run(root, "add", str(victim)))

    def test_empty_sig_file_refused_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            victim = plant(root)
            (root / "outcomes" / "cap.json.sig").write_text("", encoding="utf-8")
            self._assert_clean_refusal(run(root, "add", str(victim)))

    def test_nondict_keyfile_refused_cleanly_at_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            victim = plant(root)
            key_for(root).write_text("[1, 2]", encoding="utf-8")   # the KEY file, not the .sig
            self._assert_clean_refusal(run(root, "add", str(victim)))

    def test_short_pub_keyfile_refused_cleanly_at_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            victim = plant(root)
            k = json.loads(key_for(root).read_text(encoding="utf-8"))
            k["pub"] = "abcd"   # valid hex, wrong length
            key_for(root).write_text(json.dumps(k), encoding="utf-8")
            self._assert_clean_refusal(run(root, "add", str(victim)))


class TestBadKeyfileSignCapture(unittest.TestCase):  # R3-2
    def test_short_priv_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            k = json.loads(key_for(root).read_text(encoding="utf-8"))
            k["priv"] = "abcd"
            key_for(root).write_text(json.dumps(k), encoding="utf-8")
            cap = root / "outcomes" / "sample.json"
            cap.write_text(json.dumps({"probes": [{"technique": "T-0001", "verdict": "confirmed"}]}),
                           encoding="utf-8")
            r = run(root, "sign-capture", "outcomes/sample.json")
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("bad keyfile", (r.stdout + r.stderr))
            self.assertNotIn("Traceback", r.stderr)


class TestLazyEd25519(unittest.TestCase):  # R3-3
    def test_missing_module_keeps_non_signing_commands_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            assert run(root, "reindex").returncode == 0
            (root / "tools" / "ed25519.py").unlink()
            r = run(root, "find")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("Traceback", r.stderr)
            r = run(root, "stats")
            self.assertEqual(r.returncode, 0, r.stderr)   # stats reports, never crashes
            # signing paths fail CLOSED with the module named (sig field is well-formed
            # hex so the probe reaches the curve code, not the hex guard)
            victim = plant(root, sig={"sig": "00" * 64})
            r = run(root, "add", str(victim))
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("ed25519.py", (r.stdout + r.stderr))
            self.assertNotIn("Traceback", r.stderr)

    def test_no_bytecode_residue_in_store(self):  # R3-4c
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            rm = root / "tools" / "__pycache__"
            if rm.exists():
                shutil.rmtree(rm)
            self.assertEqual(run(root, "find").returncode, 0)
            self.assertFalse((root / "tools" / "__pycache__").exists(),
                             "no .pyc residue may be created inside the store")
            self.assertEqual(run(root, "stats").returncode, 0)
            self.assertFalse((root / "tools" / "__pycache__").exists())


class TestKeygenInStoreRefusal(unittest.TestCase):  # R3-4a (pins a review hold)
    def test_keygen_refuses_in_store_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            r = run(root, "keygen", "--keyfile", str(root / "tools" / "evil.key"))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("OUTSIDE the store", (r.stdout + r.stderr))
            self.assertFalse((root / "tools" / "evil.key").exists())


if __name__ == "__main__":
    unittest.main()