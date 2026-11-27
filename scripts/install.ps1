# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
<#
.SYNOPSIS
    Install GRAFT as a self-contained plugin or skill on Windows.
.PARAMETER Target
    Target ecosystem: antigravity, claude, codex, agents, or all.
.PARAMETER Scope
    Install scope: global (default) or project.
.PARAMETER ProjectDir
    Target project directory when -Scope project is selected.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("antigravity", "claude", "codex", "agents", "all")]
    [string]$Target,

    [ValidateSet("global", "project")]
    [string]$Scope = "global",

    [string]$ProjectDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $PythonCmd) {
    throw "Python >=3.10 is required on PATH."
}
$PythonExe = $PythonCmd.Source

function Copy-GraftStore {
    param([string]$Dest)
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    foreach ($sub in @("tools", "vocab", "techniques", "probes")) {
        Copy-Item -Path (Join-Path $RepoRoot $sub) -Destination $Dest -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $Dest "tests") | Out-Null
    Copy-Item -Path (Join-Path $RepoRoot "tests\equiv") -Destination (Join-Path $Dest "tests") -Recurse -Force
    Get-ChildItem -Path $Dest -Directory -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    $outcomes = Join-Path $Dest "outcomes"
    $sources = Join-Path $Dest "sources"
    $assets = Join-Path $Dest "assets"
    New-Item -ItemType Directory -Force -Path $outcomes, $sources, $assets | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $outcomes "ledger.jsonl"), [byte[]]@())
    [System.IO.File]::WriteAllBytes((Join-Path $sources ".gitkeep"), [byte[]]@())
    Copy-Item (Join-Path $RepoRoot "sources\README.md") (Join-Path $sources "README.md") -Force
    foreach ($f in @("LICENSE", "NOTICE", "SECURITY.md")) {
        Copy-Item (Join-Path $RepoRoot $f) (Join-Path $Dest $f) -Force
    }
    Copy-Item (Join-Path $RepoRoot "assets\logo.svg") (Join-Path $assets "logo.svg") -Force
}

function Initialize-GraftStore {
    param([string]$Dest)
    $tdb = Join-Path $Dest "tools\tdb.py"
    & $PythonExe $tdb --root $Dest init
    if ($LASTEXITCODE -ne 0) { throw "tdb init failed at $Dest" }
    & $PythonExe $tdb --root $Dest reindex
    if ($LASTEXITCODE -ne 0) { throw "tdb reindex failed at $Dest" }
    & $PythonExe $tdb --root $Dest lock-sources | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "tdb lock-sources failed at $Dest" }
    Write-Host "Installed self-contained GRAFT at: $Dest"
}

function Install-SkillDir {
    param([string]$Dest, [bool]$WithCodex)
    if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
    Copy-GraftStore -Dest $Dest
    Copy-Item (Join-Path $RepoRoot "skills\graft\SKILL.md") (Join-Path $Dest "SKILL.md") -Force
    if ($WithCodex) {
        $agentsDir = Join-Path $Dest "agents"
        New-Item -ItemType Directory -Force -Path $agentsDir | Out-Null
        Copy-Item (Join-Path $RepoRoot ".agents\skills\graft\agents\openai.yaml") (Join-Path $agentsDir "openai.yaml") -Force
    }
    Initialize-GraftStore -Dest $Dest
}

function Install-AntigravityPlugin {
    param([string]$Dest)
    if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
    Copy-GraftStore -Dest $Dest
    foreach ($sub in @("skills", "rules")) {
        Copy-Item -Path (Join-Path $RepoRoot $sub) -Destination $Dest -Recurse -Force
    }
    foreach ($f in @("plugin.json", "README.md", "AGENTS.md", "pyproject.toml")) {
        Copy-Item (Join-Path $RepoRoot $f) (Join-Path $Dest $f) -Force
    }
    Initialize-GraftStore -Dest $Dest
}

function Invoke-TargetInstall {
    param([string]$Name)
    switch ($Name) {
        "antigravity" {
            if ($Scope -eq "global") {
                Install-AntigravityPlugin -Dest (Join-Path $HOME ".gemini\config\plugins\graft")
            } else {
                Install-SkillDir -Dest (Join-Path $ProjectDir ".agents\skills\graft") -WithCodex $true
            }
        }
        "claude" {
            if ($Scope -eq "global") {
                Install-SkillDir -Dest (Join-Path $HOME ".claude\skills\graft") -WithCodex $false
            } else {
                Install-SkillDir -Dest (Join-Path $ProjectDir ".claude\skills\graft") -WithCodex $false
            }
        }
        "codex" {
            if ($Scope -eq "global") {
                Install-SkillDir -Dest (Join-Path $HOME ".codex\skills\graft") -WithCodex $true
            } else {
                Install-SkillDir -Dest (Join-Path $ProjectDir ".agents\skills\graft") -WithCodex $true
            }
        }
        "agents" {
            if ($Scope -eq "global") {
                Install-SkillDir -Dest (Join-Path $HOME ".agents\skills\graft") -WithCodex $true
            } else {
                Install-SkillDir -Dest (Join-Path $ProjectDir ".agents\skills\graft") -WithCodex $true
            }
        }
    }
}

if ($Target -eq "all") {
    foreach ($t in @("antigravity", "claude", "codex", "agents")) {
        Invoke-TargetInstall -Name $t
    }
} else {
    Invoke-TargetInstall -Name $Target
}
