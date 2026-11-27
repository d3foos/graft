#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Build self-contained Desktop/CLI distribution ZIP bundles in dist/.

Produces:
  - graft-claude-desktop-skill.zip  (Claude Desktop Upload Skill ZIP: graft/SKILL.md + self-contained store)
  - graft-codex-skill.zip           (Codex self-contained skill ZIP: graft/SKILL.md + agents/openai.yaml + store)
  - graft-antigravity-plugin.zip    (Full Antigravity plugin ZIP: graft/plugin.json + skills/graft + rules + store)
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE_DIRS = ("tools", "vocab", "techniques", "probes")
LEGAL_FILES = ("LICENSE", "NOTICE", "SECURITY.md")


def _ignore_junk(_dir: str, names: list[str]) -> set[str]:
    ignored = {"__pycache__", ".pytest_cache", "index.sqlite", "drafts", "dist"}
    for n in names:
        if n.endswith((".pyc", ".pyo", ".key", ".sig")):
            ignored.add(n)
    return ignored


def _copy_store(dst: Path) -> None:
    for sub in STORE_DIRS:
        shutil.copytree(ROOT / sub, dst / sub, ignore=_ignore_junk)
    shutil.copytree(ROOT / "tests" / "equiv", dst / "tests" / "equiv", ignore=_ignore_junk)
    (dst / "outcomes").mkdir(parents=True, exist_ok=True)
    (dst / "outcomes" / "ledger.jsonl").write_bytes(b"")
    (dst / "sources").mkdir(parents=True, exist_ok=True)
    (dst / "sources" / ".gitkeep").write_bytes(b"")
    shutil.copy2(ROOT / "sources" / "README.md", dst / "sources" / "README.md")
    for name in LEGAL_FILES:
        shutil.copy2(ROOT / name, dst / name)


def _lock_stage(stage_root: Path) -> None:
    r = subprocess.run(
        [sys.executable, str(stage_root / "tools" / "tdb.py"), "--root", str(stage_root), "lock-sources"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if r.returncode != 0:
        raise RuntimeError(f"lock-sources failed for {stage_root}: {r.stderr or r.stdout}")


def _write_zip(stage_root: Path, zip_path: Path) -> tuple[int, int]:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(stage_root.rglob("*")):
            if not file_path.is_file():
                continue
            if "__pycache__" in file_path.parts or file_path.suffix in (".pyc", ".pyo", ".key"):
                continue
            arcname = (Path("graft") / file_path.relative_to(stage_root)).as_posix()
            zf.write(file_path, arcname)
            count += 1
    return count, zip_path.stat().st_size


def build_claude_desktop_bundle(out_dir: Path) -> tuple[Path, int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "graft"
        stage.mkdir()
        _copy_store(stage)
        shutil.copy2(ROOT / "skills" / "graft" / "SKILL.md", stage / "SKILL.md")
        (stage / "assets").mkdir(exist_ok=True)
        shutil.copy2(ROOT / "assets" / "logo.svg", stage / "assets" / "logo.svg")
        _lock_stage(stage)
        dest = out_dir / "graft-claude-desktop-skill.zip"
        files, size = _write_zip(stage, dest)
        return dest, files, size


def build_codex_skill_bundle(out_dir: Path) -> tuple[Path, int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "graft"
        stage.mkdir()
        _copy_store(stage)
        shutil.copy2(ROOT / ".agents" / "skills" / "graft" / "SKILL.md", stage / "SKILL.md")
        (stage / "agents").mkdir(exist_ok=True)
        shutil.copy2(ROOT / ".agents" / "skills" / "graft" / "agents" / "openai.yaml", stage / "agents" / "openai.yaml")
        (stage / "assets").mkdir(exist_ok=True)
        shutil.copy2(ROOT / ".agents" / "skills" / "graft" / "assets" / "logo.svg", stage / "assets" / "logo.svg")
        _lock_stage(stage)
        dest = out_dir / "graft-codex-skill.zip"
        files, size = _write_zip(stage, dest)
        return dest, files, size


def build_antigravity_plugin_bundle(out_dir: Path) -> tuple[Path, int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "graft"
        stage.mkdir()
        _copy_store(stage)
        shutil.copytree(ROOT / "tests", stage / "tests", ignore=_ignore_junk, dirs_exist_ok=True)
        shutil.copytree(ROOT / "skills", stage / "skills", ignore=_ignore_junk)
        shutil.copytree(ROOT / "rules", stage / "rules", ignore=_ignore_junk)
        shutil.copytree(ROOT / "assets", stage / "assets", ignore=_ignore_junk)
        shutil.copytree(ROOT / "scripts", stage / "scripts", ignore=_ignore_junk)
        for doc in ("plugin.json", "README.md", "AGENTS.md", "pyproject.toml"):
            shutil.copy2(ROOT / doc, stage / doc)
        _lock_stage(stage)
        dest = out_dir / "graft-antigravity-plugin.zip"
        files, size = _write_zip(stage, dest)
        return dest, files, size


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build self-contained GRAFT bundles in dist/")
    ap.add_argument("--out", default=str(ROOT / "dist"), help="output directory (default: dist/)")
    args = ap.parse_args(argv)
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    for builder in (build_claude_desktop_bundle, build_codex_skill_bundle, build_antigravity_plugin_bundle):
        path, n_files, size = builder(out_dir)
        print(f"built {path.name}: {n_files} files ({size:,} bytes) -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
