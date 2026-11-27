# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Phase 2: ed25519 capture signing — closes R2-1. The record author can write records;
only the key holder can attest a run. Red on the pre-change tree: keygen/sign-capture do
not exist, and an unsigned self-authored capture is still admitted (review-2's R2-1)."""
import contextlib, importlib.util, json, os, shutil, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path

GRAFT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdb_p2", GRAFT / "tools" / "tdb.py")
tdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tdb)
spec_ed = importlib.util.spec_from_file_location("graft_ed25519", GRAFT / "tools" / "ed25519.py")
ed = importlib.util.module_from_spec(spec_ed)
spec_ed.loader.exec_module(ed)


def run(root, *args, **env):
    e = dict(os.environ)
    e.pop("GRAFT_SIGNING_KEY", None)
    e.update(env)
    return subprocess.run([sys.executable, str(Path(root) / "tools" / "tdb.py"),
                           "--root", str(root), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=e)


def fresh(tmpdir):
    root = Path(tmpdir) / "graft"
    shutil.copytree(GRAFT, root, ignore=shutil.ignore_patterns("index.sqlite", "sources.lock", "__pycache__"))
    assert run(root, "init").returncode == 0
    return root


def key_for(root):
    return Path(root).parent / (Path(root).name + "-signing.key")


def ensure_signing(root):
    """Fixture: tmp store gets its own key; any existing captures are signed with it.
    Call BEFORE planting any forged capture — this signs everything in outcomes/."""
    r = run(root, "keygen", "--keyfile", str(key_for(root)))
    assert r.returncode == 0, r.stderr
    for cap in sorted((Path(root) / "outcomes").glob("*.json")):
        if cap.name == "ledger.jsonl":
            continue
        r = run(root, "sign-capture", str(cap.relative_to(root)))
        assert r.returncode == 0, r.stderr


def load(tid, root):
    return json.loads((root / "techniques" / f"{tid}.json").read_text(encoding="utf-8"))


def plant_signed_fixture(root, tid="T-9102", cap_name="fixture-capture.json"):
    """Plant a valid locally-verified fixture record + signed capture in a tmp sandbox."""
    rec = load("T-0002", root)
    rec["id"] = tid
    rec["trust"] = "locally-verified"
    rec["mechanism"][-1]["primitive"] = "COMPARE"
    (root / "outcomes" / cap_name).write_text(json.dumps(
        {"probes": [{"technique": tid, "verdict": "confirmed"}]}), encoding="utf-8")
    rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                       "runs": [f"outcomes/{cap_name}"], "target": "lab: fixture"}
    (root / "techniques" / f"{tid}.json").write_text(json.dumps(rec), encoding="utf-8")
    assert run(root, "sign-capture", f"outcomes/{cap_name}").returncode == 0
    return root / "techniques" / f"{tid}.json"


def plant_selfauthored(root):
    """Review-2's R2-1 fixture: a probes-shaped capture authored by the record's own
    writer, naming itself. Unsigned unless someone signs it afterwards."""
    rec = load("T-0002", root)
    rec["id"] = "T-9101"; rec["trust"] = "locally-verified"
    rec["mechanism"][-1]["primitive"] = "COMPARE"
    (root / "outcomes" / "forged2.json").write_text(json.dumps(
        {"probes": [{"technique": "T-9101", "verdict": "confirmed",
                     "note": "written by the record author, not by a run"}]}), encoding="utf-8")
    rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                       "runs": ["outcomes/forged2.json"], "target": "lab: nowhere"}
    (root / "techniques" / "T-9101.json").write_text(json.dumps(rec), encoding="utf-8")
    return root / "techniques" / "T-9101.json"


class TestEd25519(unittest.TestCase):
    def test_rfc8032_test1_key_derivation(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(ed.publickey(seed).hex(),
                         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    def test_sign_verify_roundtrip_and_tamper(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = ed.publickey(seed)
        for msg in (b"", b"graft capture bytes", os.urandom(64)):
            sig = ed.signature(seed, msg)
            ok, _ = ed.checkvalid(sig, msg, pk)
            self.assertTrue(ok)
            bad, reason = ed.checkvalid(sig, msg + b"x", pk)
            self.assertFalse(bad)
            bad2, _ = ed.checkvalid(sig[:31] + bytes([sig[31] ^ 1]) + sig[32:], msg, pk)
            self.assertFalse(bad2, "a flipped signature bit must not verify")


class TestKeygenCLI(unittest.TestCase):
    def test_keygen_creates_key_outside_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            r = run(root, "keygen")
            self.assertEqual(r.returncode, 0, r.stderr)
            key = key_for(root)
            self.assertTrue(key.exists())
            self.assertFalse(key.is_relative_to(root.resolve()), "the key must live outside the store")
            if os.name != "nt":
                self.assertEqual((key.stat().st_mode & 0o777), 0o600, "key must be private")
            data = json.loads(key.read_text(encoding="utf-8"))
            self.assertEqual(data["alg"], "ed25519")
            self.assertIn("key_id", r.stdout)

    def test_keygen_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            assert run(root, "keygen").returncode == 0
            before = key_for(root).read_text(encoding="utf-8")
            r = run(root, "keygen")
            self.assertNotEqual(r.returncode, 0, "key rotation must not be silent")
            self.assertIn("force", (r.stdout + r.stderr))
            self.assertEqual(key_for(root).read_text(encoding="utf-8"), before)
            self.assertEqual(run(root, "keygen", "--force").returncode, 0)


class TestSignCaptureCLI(unittest.TestCase):
    def test_signs_capture_and_gate_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            assert run(root, "keygen").returncode == 0
            cap = "outcomes/fixture-capture.json"
            (root / cap).write_text(json.dumps({"probes": [{"technique": "T-0001", "verdict": "confirmed"}]}),
                                     encoding="utf-8")
            r = run(root, "sign-capture", cap)
            self.assertEqual(r.returncode, 0, r.stderr)
            sig = json.loads((root / (cap + ".sig")).read_text(encoding="utf-8"))
            self.assertEqual(sig["alg"], "ed25519")
            data = json.loads(key_for(root).read_text(encoding="utf-8"))
            self.assertEqual(sig["key_id"], data["key_id"])

    def test_sign_capture_clean_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            r = run(root, "sign-capture", "outcomes/no-such.json")
            self.assertEqual(r.returncode, 2)
            self.assertNotIn("Traceback", r.stderr)
            outside = Path(tmp) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            r = run(root, "sign-capture", str(outside.resolve()))
            self.assertEqual(r.returncode, 2, "captures outside the root must be refused")
            self.assertNotIn("Traceback", r.stderr)


class TestGateRequiresSignature(unittest.TestCase):
    """The R2-1 reversal: a self-authored probes-shaped capture naming itself must be
    refused unless the store's key signed it."""

    def _selfauthored(self, root):
        return plant_selfauthored(root)

    def test_unsigned_selfauthored_capture_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)  # key exists and real captures are signed
            victim = self._selfauthored(root)  # planted AFTER signing: forged2 stays unsigned
            r = run(root, "add", str(victim))
            self.assertNotEqual(r.returncode, 0, "R2-1: unsigned capture must not reach locally-verified")
            out = r.stdout + r.stderr
            self.assertIn("unsigned", out)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                n = db.execute("SELECT count(*) FROM tech WHERE id='T-9101'").fetchone()[0]
            self.assertEqual(n, 0)

    def test_attacker_keyed_capture_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)
            victim = self._selfauthored(root)
            attacker_key = Path(tmp) / "attacker.key"
            assert run(root, "keygen", "--keyfile", str(attacker_key)).returncode == 0
            r = run(root, "sign-capture", "outcomes/forged2.json", "--keyfile", str(attacker_key))
            self.assertEqual(r.returncode, 0, "signing with an attacker key is allowed — the gate must reject it")
            r = run(root, "add", str(victim))
            self.assertNotEqual(r.returncode, 0, "a capture signed by a foreign key must not verify")
            self.assertIn("verification failed", (r.stdout + r.stderr))

    def test_tampered_capture_content_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)
            victim = self._selfauthored(root)
            # the store owner's own key signs the capture — then the content is edited
            assert run(root, "sign-capture", "outcomes/forged2.json").returncode == 0
            p = root / "outcomes" / "forged2.json"
            p.write_text(p.read_text(encoding="utf-8").replace("confirmed", "confirmed "), encoding="utf-8")  # one byte
            r = run(root, "add", str(victim))
            self.assertNotEqual(r.returncode, 0, "post-signature tampering must fail verification")

    def test_missing_sig_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)
            victim = self._selfauthored(root)
            assert run(root, "sign-capture", "outcomes/forged2.json").returncode == 0
            (root / "outcomes" / "forged2.json.sig").unlink()
            r = run(root, "add", str(victim))
            self.assertNotEqual(r.returncode, 0, "a deleted .sig must fail the gate")
            self.assertIn("unsigned", (r.stdout + r.stderr))

    def test_no_key_fails_closed_with_remedy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            victim = self._selfauthored(root)
            r = run(root, "add", str(victim))  # no key anywhere
            self.assertNotEqual(r.returncode, 0, "missing key must fail closed, not open")
            out = r.stdout + r.stderr
            self.assertIn("no signing key", out)
            self.assertIn("keygen", out)

    def test_signed_legitimate_record_admitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)
            plant_signed_fixture(root, tid="T-9102")
            r = run(root, "add", *[str(p) for p in sorted((root / "techniques").glob("T-*.json"))])
            self.assertEqual(r.returncode, 0, r.stderr)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                trust = dict(db.execute("SELECT id, trust FROM tech").fetchall())
            self.assertEqual(trust["T-0001"], "corroborated")
            self.assertEqual(trust["T-0005"], "corroborated")
            self.assertEqual(trust["T-9102"], "locally-verified")


class TestKeyLossRecovery(unittest.TestCase):
    def test_reindex_without_key_skips_lv_records_loudly_and_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)
            plant_signed_fixture(root, tid="T-9102")
            assert run(root, "reindex").returncode == 0
            key_for(root).unlink()  # key lost
            r = run(root, "reindex")
            self.assertNotEqual(r.returncode, 0, "missing key must fail closed at reindex too")
            out = r.stdout + r.stderr
            self.assertIn("no signing key", out)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                n = dict(db.execute("SELECT id, trust FROM tech").fetchall())
            self.assertNotIn("T-9102", n, "unsigned-capture records must be skipped")
            self.assertIn("T-0002", n, "clean records must still index")
            # recovery: a fresh key + re-sign restores the tier
            ensure_signing(root)
            r = run(root, "reindex")
            self.assertEqual(r.returncode, 0, r.stderr)
            with contextlib.closing(sqlite3.connect(root / "index.sqlite")) as db:
                n = dict(db.execute("SELECT id, trust FROM tech").fetchall())
            self.assertEqual(n["T-9102"], "locally-verified")

    def test_stats_flags_unsigned_capture_from_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)
            plant_selfauthored(root)  # unsigned forged capture stays in the store
            r = run(root, "stats")
            out = r.stdout + r.stderr
            self.assertIn("unsigned", out)


class TestPromoteWiring(unittest.TestCase):
    def test_promote_to_locally_verified_requires_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fresh(tmp)
            ensure_signing(root)
            assert run(root, "add", str(root / "techniques" / "T-0002.json")).returncode == 0
            # T-0002 is corroborated with web evidence; promote demands reproduced_local
            # evidence citing a SIGNED capture — give it one unsigned and watch the gate.
            rec = load("T-0002", root)
            rec["evidence"] = {"status": "reproduced_local", "gate": "external_oracle",
                               "runs": ["outcomes/forged-promote.json"], "target": "lab"}
            (root / "outcomes" / "forged-promote.json").write_text(json.dumps(
                {"probes": [{"technique": "T-0002", "verdict": "confirmed"}]}), encoding="utf-8")
            (root / "techniques" / "T-0002.json").write_text(json.dumps(rec), encoding="utf-8")
            r = run(root, "promote", "T-0002", "--to", "locally-verified")
            self.assertNotEqual(r.returncode, 0, "promote must run the signature gate")
            self.assertIn("unsigned", (r.stdout + r.stderr))


if __name__ == "__main__":
    unittest.main()