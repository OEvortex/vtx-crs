"""Repository analyzer tool: maps an unknown codebase (languages, build,
test framework, entry points, structure)."""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import get_case_manager

from ._common import IGNORED_DIRS, MAX_FILE_BYTES, is_ignored_dir, resolve_repo_path

_case_manager = get_case_manager()

EXTENSION_LANGUAGE = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".rb": "Ruby",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".sql": "SQL",
    ".swift": "Swift",
    ".scala": "Scala",
    ".lua": "Lua",
    ".r": "R",
    ".vue": "Vue",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "SCSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown",
    ".txt": "Text",
    ".proto": "Protobuf",
    ".dockerfile": "Dockerfile",
    ".tf": "Terraform",
    ".zig": "Zig",
    ".ex": "Elixir",
    ".exs": "Elixir",
}

BUILD_SYSTEMS = [
    ("pyproject.toml", "Python (PEP 621 + hatchling/pyproject build)"),
    ("setup.py", "Python (setuptools)"),
    ("setup.cfg", "Python (setuptools)"),
    ("requirements.txt", "Python (pip requirements)"),
    ("Cargo.toml", "Rust (Cargo)"),
    ("package.json", "Node.js (npm/yarn/pnpm)"),
    ("go.mod", "Go (modules)"),
    ("Makefile", "Make"),
    ("makefile", "Make"),
    ("CMakeLists.txt", "CMake"),
    ("pom.xml", "Java (Maven)"),
    ("build.gradle", "Java/Groovy (Gradle)"),
    ("settings.gradle", "Java/Groovy (Gradle)"),
    ("mix.exs", "Elixir (Mix)"),
    ("composer.json", "PHP (Composer)"),
    ("Gemfile", "Ruby (Bundler)"),
    ("Dockerfile", "Container (Docker)"),
]

ENTRY_POINT_PATTERNS = [
    "__main__.py",
    "main.py",
    "app.py",
    "cli.py",
    "manage.py",
    "index.js",
    "index.ts",
    "main.go",
    "src/main.rs",
]


class RepoAnalyzeParams(BaseModel):
    repo_path: str = ""
    depth: int = 2


class RepoAnalyzerTool(BaseTool[RepoAnalyzeParams]):
    name = "repo_analyze"
    description = (
        "Map an unknown source code repository: languages, build system, test framework, "
        "entry points, directory structure, and size. Call this first to understand a "
        "new codebase before reading files."
    )
    params = RepoAnalyzeParams
    mutating = False
    prompt_guidelines = (
        "Call repo_analyze first on any new target repository.",
        "After mapping, read the manifest/build files and the entry points listed.",
    )

    async def execute(
        self, params: RepoAnalyzeParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        lines: list[str] = [f"Repository: {repo}", ""]

        # VCS / git state
        git_lines = self._git_info(repo)
        if git_lines:
            lines.extend(git_lines)
            lines.append("")

        # Languages
        lang_files: Counter[str] = Counter()
        lang_lines: Counter[str] = Counter()
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(repo):
            dirnames[:] = [d for d in dirnames if not is_ignored_dir(d) and not d.startswith(".")]
            for filename in filenames:
                file_count += 1
                suffix = Path(filename).suffix.lower()
                lang = EXTENSION_LANGUAGE.get(suffix)
                if lang is None:
                    continue
                lang_files[lang] += 1
                path = Path(dirpath) / filename
                try:
                    if path.stat().st_size <= MAX_FILE_BYTES:
                        with open(path, encoding="utf-8", errors="ignore") as f:
                            lang_lines[lang] += sum(1 for _ in f)
                except OSError:
                    pass

        lines.append(f"Files: {file_count}")
        if lang_files:
            lines.append("\nLanguages:")
            for lang, count in lang_files.most_common(12):
                lc = lang_lines.get(lang, 0)
                lines.append(f"  - {lang}: {count} file(s), ~{lc:,} lines")
            lines.append("")

        # Build system
        build = self._detect_build(repo)
        lines.append("Build system:")
        if build:
            for label, detail in build:
                lines.append(f"  - {label}: {detail}")
        else:
            lines.append("  - None detected")
        lines.append("")

        # Test framework
        test = self._detect_test_framework(repo, build)
        lines.append("Test framework:")
        if test:
            for t in test:
                lines.append(f"  - {t}")
        else:
            lines.append("  - None detected")
        lines.append("")

        # Entry points
        entry = self._detect_entry_points(repo)
        if entry:
            lines.append("Entry points:")
            for e in entry:
                lines.append(f"  - {e}")
            lines.append("")

        # Structure
        lines.append(f"Directory structure (depth {max(1, min(params.depth, 4))}):")
        structure = self._structure(repo, depth=max(1, min(params.depth, 4)))
        lines.extend(structure or ["  (empty)"])
        lines.append("")

        result_text = "\n".join(lines)
        top_langs = ", ".join(lang for lang, _ in lang_files.most_common(4)) or "unknown"
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{file_count} files | {top_langs}",
            ui_details=result_text,
        )

    @staticmethod
    def _git_info(repo: Path) -> list[str]:
        if not (repo / ".git").exists():
            return []
        try:
            out = subprocess.run(
                ["git", "-C", str(repo), "log", "-1", "--oneline"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            head = out.stdout.strip() or "no commits"
            branch = subprocess.run(
                ["git", "-C", str(repo), "branch", "--show-current"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            dirty = subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
            n_dirty = len([l for l in dirty.splitlines() if l.strip()])
            return [
                "VCS: git",
                f"  branch: {branch or 'detached/unknown'}",
                f"  HEAD: {head}",
                f"  uncommitted changes: {n_dirty}",
            ]
        except Exception:
            return ["VCS: git (state unavailable)"]

    @staticmethod
    def _detect_build(repo: Path) -> list[tuple[str, str]]:
        found = []
        for filename, label in BUILD_SYSTEMS:
            if (repo / filename).exists():
                found.append((filename, label))
        if (repo / "pyproject.toml").exists():
            content = (repo / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
            if "[tool.uv]" in content or (repo / "uv.lock").exists():
                found.append(("uv", "Python package manager: uv"))
            if "[tool.poetry]" in content:
                found.append(("poetry", "Python package manager: poetry"))
            if "[tool.pdm" in content:
                found.append(("pdm", "Python package manager: pdm"))
        if (repo / "package.json").exists():
            for lock in ("pnpm-lock.yaml", "yarn.lock", "package-lock.json", "bun.lockb"):
                if (repo / lock).exists():
                    found.append((lock, f"Node lockfile: {lock}"))
                    break
        return found

    @staticmethod
    def _detect_test_framework(repo: Path, build: list[tuple[str, str]]) -> list[str]:
        tests = []
        if (repo / "pytest.ini").exists() or (repo / "tox.ini").exists():
            tests.append("pytest (pytest.ini/tox.ini)")
        if (repo / "pyproject.toml").exists():
            content = (repo / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
            if "[tool.pytest.ini_options]" in content:
                tests.append("pytest (pyproject.toml)")
            if "pytest" in content:
                tests.append("pytest (referenced in pyproject.toml)")
        if (repo / "requirements-dev.txt").exists():
            content = (repo / "requirements-dev.txt").read_text(encoding="utf-8", errors="ignore")
            if "pytest" in content:
                tests.append("pytest (requirements-dev.txt)")
        if (repo / "package.json").exists():
            import json as _json

            try:
                data = _json.loads((repo / "package.json").read_text(encoding="utf-8"))
                script = (data.get("scripts") or {}).get("test", "")
                if script:
                    tests.append(f"Node test script: {script}")
            except Exception:
                pass
        if (repo / "Makefile").exists() or (repo / "makefile").exists():
            content = (
                (repo / "Makefile").read_text(encoding="utf-8", errors="ignore")
                if (repo / "Makefile").exists()
                else (repo / "makefile").read_text(encoding="utf-8", errors="ignore")
            )
            if re_search_test_target(content):
                tests.append("make test")
        if (repo / "Cargo.toml").exists():
            tests.append("cargo test")
        if list(repo.glob("**/*_test.go"))[:1]:
            tests.append("go test")
        if (repo / "pom.xml").exists():
            tests.append("Maven surefire (mvn test)")
        return tests

    @staticmethod
    def _detect_entry_points(repo: Path) -> list[str]:
        found = []
        for pattern in ENTRY_POINT_PATTERNS:
            for path in repo.rglob(pattern):
                if is_ignored_dir(path.parent.name) or any(
                    part in IGNORED_DIRS for part in path.relative_to(repo).parts[:-1]
                ):
                    continue
                found.append(str(path.relative_to(repo)))
                break  # one per pattern
        for cmd_dir in ("cmd", "bin"):
            cmd = repo / cmd_dir
            if cmd.is_dir():
                for entry in sorted(cmd.iterdir())[:5]:
                    found.append(f"{cmd_dir}/{entry.name}")
        return found

    @staticmethod
    def _structure(repo: Path, depth: int) -> list[str]:
        rows: list[str] = []

        def walk(path: Path, level: int, prefix: str = "") -> None:
            if level > depth:
                return
            try:
                entries = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
            except OSError:
                return
            dirs = [
                e
                for e in entries
                if e.is_dir() and not is_ignored_dir(e.name) and not e.name.startswith(".")
            ]
            files = [e for e in entries if e.is_file()]
            for i, d in enumerate(dirs):
                last = i == len(dirs) - 1 and not files
                branch = "└── " if last else "├── "
                rows.append(f"{prefix}{branch}{d.name}/")
                walk(d, level + 1, prefix + ("    " if last else "│   "))
            for i, f in enumerate(files):
                last = i == len(files) - 1
                branch = "└── " if last else "├── "
                if f.name in ("__init__.py", "index.js", "main.go", "main.py"):
                    rows.append(f"{prefix}{branch}{f.name}  (entry)")
                else:
                    rows.append(f"{prefix}{branch}{f.name}")

        for entry in sorted(repo.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            if entry.name.startswith(".") or is_ignored_dir(entry.name):
                continue
            if entry.is_dir():
                rows.append(f"{entry.name}/")
                walk(entry, 2)
            else:
                rows.append(entry.name)
        return rows[:300]  # cap output size


def re_search_test_target(content: str) -> bool:
    import re

    return bool(re.search(r"^test\s*:", content, re.MULTILINE))
