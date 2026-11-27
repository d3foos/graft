#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
# Cross-platform macOS/Linux installer for GRAFT across Antigravity, Claude Code, Codex, and Agent Skills.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STORE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${STORE_ROOT}/.." && pwd)"

TARGET=""
SCOPE="global"
PROJECT_DIR="$(pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/install.sh --target <antigravity|claude|codex|agents|all> [--scope <global|project>] [--project-dir <dir>]

Targets:
  antigravity   Install full self-contained plugin (~/.gemini/config/plugins/graft or <project>/.agents/skills/graft)
  claude        Install self-contained skill (~/.claude/skills/graft or <project>/.claude/skills/graft)
  codex         Install self-contained skill (~/.codex/skills/graft or <project>/.agents/skills/graft)
  agents        Install self-contained skill (~/.agents/skills/graft or <project>/.agents/skills/graft)
  all           Install across all four global targets
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2 ;;
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --project-dir) PROJECT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "${TARGET}" ]]; then
  usage
  exit 2
fi

if [[ "${SCOPE}" != "global" && "${SCOPE}" != "project" ]]; then
  echo "ERROR: --scope must be global or project" >&2
  exit 2
fi

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "ERROR: Python >=3.10 is required on PATH" >&2
  exit 1
fi

copy_store() {
  local dest="$1"
  mkdir -p "${dest}/outcomes" "${dest}/sources" "${dest}/tests" "${dest}/assets"
  cp -R "${STORE_ROOT}/tools" "${dest}/"
  cp -R "${STORE_ROOT}/vocab" "${dest}/"
  cp -R "${STORE_ROOT}/techniques" "${dest}/"
  cp -R "${STORE_ROOT}/probes" "${dest}/"
  cp -R "${STORE_ROOT}/tests/equiv" "${dest}/tests/"
  find "${dest}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  : > "${dest}/outcomes/ledger.jsonl"
  : > "${dest}/sources/.gitkeep"
  cp "${STORE_ROOT}/sources/README.md" "${dest}/sources/README.md"
  cp "${REPO_ROOT}/LICENSE" "${dest}/LICENSE"
  cp "${REPO_ROOT}/NOTICE" "${dest}/NOTICE"
  cp "${REPO_ROOT}/.github/SECURITY.md" "${dest}/SECURITY.md"
  cp "${REPO_ROOT}/skills/graft/assets/logo.svg" "${dest}/assets/logo.svg"
}

init_store() {
  local dest="$1"
  "${PYTHON_BIN}" "${dest}/tools/tdb.py" --root "${dest}" init
  "${PYTHON_BIN}" "${dest}/tools/tdb.py" --root "${dest}" reindex
  "${PYTHON_BIN}" "${dest}/tools/tdb.py" --root "${dest}" lock-sources >/dev/null
  echo "Installed self-contained GRAFT at: ${dest}"
}

install_skill_dir() {
  local dest="$1"
  local with_codex="$2"
  rm -rf "${dest}"
  mkdir -p "${dest}"
  copy_store "${dest}"
  cp "${REPO_ROOT}/skills/graft/SKILL.md" "${dest}/SKILL.md"
  if [[ "${with_codex}" == "1" ]]; then
    mkdir -p "${dest}/agents"
    cp "${REPO_ROOT}/.agents/skills/graft/agents/openai.yaml" "${dest}/agents/openai.yaml"
  fi
  init_store "${dest}"
}

install_antigravity_plugin() {
  local dest="$1"
  rm -rf "${dest}"
  mkdir -p "${dest}"
  copy_store "${dest}"
  cp -R "${REPO_ROOT}/skills" "${dest}/"
  cp -R "${REPO_ROOT}/rules" "${dest}/"
  cp "${REPO_ROOT}/plugin.json" "${dest}/plugin.json"
  cp "${REPO_ROOT}/README.md" "${dest}/README.md"
  cp "${REPO_ROOT}/AGENTS.md" "${dest}/AGENTS.md"
  cp "${REPO_ROOT}/pyproject.toml" "${dest}/pyproject.toml"
  init_store "${dest}"
}

run_target() {
  local t="$1"
  case "${t}" in
    antigravity)
      if [[ "${SCOPE}" == "global" ]]; then
        install_antigravity_plugin "${HOME}/.gemini/config/plugins/graft"
      else
        install_skill_dir "${PROJECT_DIR}/.agents/skills/graft" "1"
      fi
      ;;
    claude)
      if [[ "${SCOPE}" == "global" ]]; then
        install_skill_dir "${HOME}/.claude/skills/graft" "0"
      else
        install_skill_dir "${PROJECT_DIR}/.claude/skills/graft" "0"
      fi
      ;;
    codex)
      if [[ "${SCOPE}" == "global" ]]; then
        install_skill_dir "${HOME}/.codex/skills/graft" "1"
      else
        install_skill_dir "${PROJECT_DIR}/.agents/skills/graft" "1"
      fi
      ;;
    agents)
      if [[ "${SCOPE}" == "global" ]]; then
        install_skill_dir "${HOME}/.agents/skills/graft" "1"
      else
        install_skill_dir "${PROJECT_DIR}/.agents/skills/graft" "1"
      fi
      ;;
    *)
      echo "ERROR: unsupported target '${t}'" >&2
      exit 2
      ;;
  esac
}

if [[ "${TARGET}" == "all" ]]; then
  run_target antigravity
  run_target claude
  run_target codex
  run_target agents
else
  run_target "${TARGET}"
fi
