# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Cross-ecosystem packaging, manifest, sync, bundle, and leak-free verification tests."""
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

STORE = Path(__file__).resolve().parent.parent
GRAFT = STORE.parent

ANTIGRAVITY_ALLOWED_KEYS = {
    "name",
    "displayName",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "logo",
    "suggestedPrompts",
    "disabled",
}

FORBIDDEN_LEAK_REGEX = re.compile(
    r"re200|rt-be92u|192\.168\.|c-cyber|ax55|ax3000|msdu11|/output/graft|C:\\\\Users|C:\\Users|/data/\.agents/skills|graft-technique-transfer-tool\.md|graft-design-review\.md",
    re.IGNORECASE,
)


def parse_frontmatter(md_text: str) -> dict[str, str]:
    lines = md_text.splitlines()
    assert lines and lines[0].strip() == "---", "Missing opening YAML frontmatter"
    end_idx = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break
    assert end_idx is not None, "Missing closing YAML frontmatter"
    fields: dict[str, str] = {}
    current_key = None
    for line in lines[1:end_idx]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and ":" in line:
            k, v = line.split(":", 1)
            current_key = k.strip()
            fields[current_key] = v.strip()
    return fields


class TestLegalAndProjectMetadata(unittest.TestCase):
    def test_agpl_license_complete_verbatim(self):
        lic = (GRAFT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", lic)
        self.assertIn("Version 3, 19 November 2007", lic)
        self.assertIn("END OF TERMS AND CONDITIONS", lic)
        self.assertGreaterEqual(len(lic.splitlines()), 650)

    def test_notice_and_security_present(self):
        notice = (GRAFT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("Abdulrahman Almuhairi", notice)
        self.assertIn("AGPL-3.0", notice)
        sec = (GRAFT / ".github" / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("offline", sec.lower())
        self.assertIn("authorized", sec.lower())

    def test_pyproject_toml_valid(self):
        data = tomllib.loads((GRAFT / "pyproject.toml").read_text(encoding="utf-8"))
        proj = data["project"]
        self.assertEqual(proj["name"], "graft-tdb")
        self.assertEqual(proj["license"], "AGPL-3.0-or-later")
        self.assertEqual(proj["dependencies"], [])
        self.assertIn("graft-tdb", proj["scripts"])
        self.assertIn("tdb", proj["scripts"])


class TestMultiPlatformManifests(unittest.TestCase):
    def test_antigravity_plugin_json_strict(self):
        data = json.loads((GRAFT / "plugin.json").read_text(encoding="utf-8"))
        unknown = set(data) - ANTIGRAVITY_ALLOWED_KEYS
        self.assertEqual(unknown, set(), f"Unknown Antigravity plugin.json keys: {unknown}")
        self.assertEqual(data["name"], "graft")
        self.assertTrue((GRAFT / data["logo"]).is_file())
        self.assertLessEqual(len(data.get("suggestedPrompts", [])), 3)
        self.assertTrue((GRAFT / "skills" / "graft" / "SKILL.md").is_file())
        self.assertTrue((GRAFT / "rules" / "AGENTS.md").is_file())

    def test_claude_plugin_and_marketplace_json(self):
        plug = json.loads((GRAFT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(plug["name"], "graft")
        self.assertEqual(plug["license"], "AGPL-3.0-or-later")
        mkt = json.loads((GRAFT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        self.assertEqual(mkt["name"], "graft")
        self.assertEqual(mkt["owner"]["name"], "Abdulrahman Almuhairi")
        self.assertEqual(len(mkt["plugins"]), 1)
        self.assertEqual(mkt["plugins"][0]["source"], "./")

    def test_codex_openai_yaml(self):
        yaml_path = GRAFT / ".agents" / "skills" / "graft" / "agents" / "openai.yaml"
        txt = yaml_path.read_text(encoding="utf-8")
        self.assertIn("interface:", txt)
        self.assertIn("display_name:", txt)
        self.assertIn("short_description:", txt)
        self.assertIn("icon_small:", txt)
        self.assertIn("icon_large:", txt)
        self.assertIn("default_prompt:", txt)
        self.assertIn("$graft", txt)
        self.assertIn("allow_implicit_invocation: true", txt)
        skill_dir = yaml_path.parent.parent
        for m in re.finditer(r'icon_(?:small|large):\s*"([^"]+)"', txt):
            rel = m.group(1)
            self.assertTrue((skill_dir / rel).is_file(), f"Missing icon: {rel}")

    def test_skill_mirrors_and_icons_synced(self):
        s1 = (GRAFT / "skills" / "graft" / "SKILL.md").read_bytes()
        s2 = (GRAFT / ".agents" / "skills" / "graft" / "SKILL.md").read_bytes()
        self.assertEqual(s1, s2, "skills/graft/SKILL.md and .agents/skills/graft/SKILL.md must stay synced")
        fm = parse_frontmatter(s1.decode("utf-8"))
        self.assertEqual(fm.get("name"), "graft")
        self.assertEqual(fm.get("license"), "AGPL-3.0-or-later")
        self.assertTrue(fm.get("description"))

        skill_logo = (GRAFT / "skills" / "graft" / "assets" / "logo.svg").read_bytes()
        self.assertEqual(skill_logo, (GRAFT / ".agents" / "skills" / "graft" / "assets" / "logo.svg").read_bytes())

    def test_no_symlinks_in_repo(self):
        symlinks = [p for p in GRAFT.rglob("*") if p.is_symlink()]
        self.assertEqual(symlinks, [], f"Symlinks break Windows/ZIP installs: {symlinks}")


class TestSanitizationAndBundles(unittest.TestCase):
    def test_no_private_leaks_or_hardcoded_paths(self):
        hits = []
        skip_parts = {".git", "__pycache__", "dist", ".pytest_cache"}
        for p in sorted(GRAFT.rglob("*")):
            if not p.is_file() or skip_parts.intersection(p.parts):
                continue
            if p.name == "test_packaging.py":
                continue
            if p.suffix in (".json", ".md", ".py", ".yaml", ".yml", ".toml", ".sh", ".ps1", ".svg", ".txt", ".jsonl"):
                text = p.read_text(encoding="utf-8", errors="ignore")
                if FORBIDDEN_LEAK_REGEX.search(text):
                    hits.append(p.relative_to(GRAFT).as_posix())
        self.assertEqual(hits, [], f"Unexpected private/hardcoded strings in: {hits}")

    def test_sources_and_outcomes_clean(self):
        src_files = [p.name for p in (STORE / "sources").iterdir() if p.is_file()]
        self.assertEqual(sorted(src_files), [".gitkeep", "README.md"])
        out_files = [p.name for p in (STORE / "outcomes").iterdir() if p.is_file()]
        self.assertEqual(out_files, ["ledger.jsonl"])
        self.assertEqual((STORE / "outcomes" / "ledger.jsonl").stat().st_size, 0)

    def test_build_bundles_self_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            r = subprocess.run(
                [sys.executable, str(STORE / "scripts" / "build-bundles.py"), "--out", str(out)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            expected = {
                "graft-claude-desktop-skill.zip": ["graft/SKILL.md", "graft/tools/tdb.py", "graft/sources.lock"],
                "graft-codex-skill.zip": [
                    "graft/SKILL.md",
                    "graft/agents/openai.yaml",
                    "graft/tools/tdb.py",
                    "graft/sources.lock",
                ],
                "graft-antigravity-plugin.zip": [
                    "graft/plugin.json",
                    "graft/skills/graft/SKILL.md",
                    "graft/rules/AGENTS.md",
                    "graft/tools/tdb.py",
                    "graft/sources.lock",
                ],
            }
            for zname, required in expected.items():
                zp = out / zname
                self.assertTrue(zp.is_file(), f"Missing bundle: {zname}")
                with zipfile.ZipFile(zp) as zf:
                    names = set(zf.namelist())
                    self.assertTrue(all(n.startswith("graft/") for n in names), f"Non-root entry in {zname}")
                    for req in required:
                        self.assertIn(req, names, f"{zname} missing {req}")
                    self.assertFalse(any(n.endswith(("index.sqlite", ".key", ".pyc")) for n in names))


if __name__ == "__main__":
    unittest.main()
