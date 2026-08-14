"""Shared helpers for CRS tools."""

from __future__ import annotations

import os
from pathlib import Path

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    "out",
    "vendor",
    "coverage",
    ".idea",
    ".vscode",
    ".DS_Store",
    "site-packages",
}

MAX_FILE_BYTES = 1_000_000  # skip scanning/reading files larger than 1 MB


def resolve_repo_path(requested: str, fallback_repo: str = "") -> Path:
    """Resolve the repository path for a tool call.

    Priority: explicit parameter > active case repo > current working dir.
    """
    candidate = requested.strip() or fallback_repo.strip()
    if not candidate:
        candidate = os.getcwd()
    return Path(candidate).expanduser().resolve()


def is_ignored_dir(name: str) -> bool:
    return name in IGNORED_DIRS


def iter_source_files(root: Path, extensions: set[str] | None = None, max_files: int = 20_000):
    """Yield source file paths under ``root``, skipping ignored directories."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not is_ignored_dir(d) and not d.startswith(".")]
        for filename in filenames:
            if count >= max_files:
                return
            path = Path(dirpath) / filename
            if path.suffix.lower() not in (extensions or set()):
                continue
            count += 1
            yield path
