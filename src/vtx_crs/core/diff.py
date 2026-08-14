"""Unified diff parsing and application (pure Python, no external deps).

Implements a tolerant subset of ``git diff`` / ``patch`` unified format:

* file headers ``--- a/path`` / ``+++ b/path``
* hunks ``@@ -old_start,old_count +new_start,new_count @@``
* context (`` ``), added (``+``), removed (``-``) lines
* ``\\ No newline at end of file`` markers
* multiple files and multiple hunks per diff

Context matching is fuzzy: if the exact old line numbers do not match, the
hunk is searched forward and backward for a position where every context
line matches in order. This makes the applier resilient to small drifts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    # Each entry is (marker, text): marker in {" ", "+", "-"}
    lines: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def target_path(self) -> str:
        return _normalize_path(self.new_path) or _normalize_path(self.old_path)


@dataclass
class ApplyResult:
    success: bool
    message: str
    changed_files: list[str] = field(default_factory=list)
    rejected_hunks: int = 0


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_HEADER_RE = re.compile(r"^--- (.+)$")


def _normalize_path(path: str) -> str:
    """Strip common diff prefixes (a/, b/) and git dev/null markers."""
    path = path.strip()
    if path in {"/dev/null", "dev/null"}:
        return ""
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    # Timestamp suffix (e.g. "file.py\t2024-01-01 ...") — keep only path.
    if "\t" in path:
        path = path.split("\t", 1)[0]
    return path


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """Parse unified diff text into FileDiff objects (skips binary diffs)."""
    files: list[FileDiff] = []
    current: FileDiff | None = None
    current_hunk: Hunk | None = None

    for raw_line in diff_text.splitlines():
        line = raw_line
        if line.startswith("diff --git "):
            if current is not None:
                files.append(current)
            current = None
            current_hunk = None
            continue

        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            if current is not None:
                files.append(current)
                current = None
                current_hunk = None
            continue

        if line.startswith("--- ") or line.startswith("+++ "):
            if current is None:
                current = FileDiff(old_path="", new_path="")
            if line.startswith("--- ") and not current.old_path:
                current.old_path = _normalize_path(line[4:])
            elif line.startswith("+++ ") and not current.new_path:
                current.new_path = _normalize_path(line[4:])
            current_hunk = None
            continue

        m = _HUNK_RE.match(line)
        if m:
            if current is None:
                current = FileDiff(old_path="", new_path="")
            current_hunk = Hunk(
                old_start=int(m.group(1)),
                old_count=int(m.group(2) or 1),
                new_start=int(m.group(3)),
                new_count=int(m.group(4) or 1),
            )
            current.hunks.append(current_hunk)
            continue

        if current_hunk is not None:
            if line == "\\ No newline at end of file":
                continue
            if line.startswith(" "):
                current_hunk.lines.append((" ", line[1:]))
            elif line.startswith("+"):
                current_hunk.lines.append(("+", line[1:]))
            elif line.startswith("-"):
                current_hunk.lines.append(("-", line[1:]))
            else:
                # Unrecognized line (e.g. stray header) ends the hunk.
                current_hunk = None

    if current is not None:
        files.append(current)

    return [f for f in files if f.hunks and f.target_path]


def _original_block(hunk: Hunk) -> list[str]:
    """The contiguous block of lines the hunk expects in the original file.

    Context and removed lines appear in the original file in hunk order;
    added lines do not.
    """
    return [text for marker, text in hunk.lines if marker in (" ", "-")]


def _block_matches(lines: list[str], pos: int, block: list[str]) -> bool:
    if pos + len(block) > len(lines):
        return False
    return all(lines[pos + i] == expected for i, expected in enumerate(block))


def _find_hunk_position(lines: list[str], hunk: Hunk, search_radius: int = 40) -> int | None:
    """Locate a 0-based index where the hunk's original block starts.

    Tries the exact old_start position first, then scans within
    ``search_radius`` lines for a window where the block matches in order.
    Returns None when no match is found.
    """
    block = _original_block(hunk)
    if not block:
        # Pure addition hunk: position is right after the previous line.
        return max(0, hunk.old_start - 1)

    # Prefer the exact position derived from the header.
    start = max(0, hunk.old_start - 1)
    if _block_matches(lines, start, block):
        return start
    for pos in range(max(0, start - search_radius), min(len(lines), start + search_radius + 1)):
        if pos == start:
            continue
        if _block_matches(lines, pos, block):
            return pos

    # Fall back to scanning the whole file for the first block line.
    first = block[0]
    for i, line in enumerate(lines):
        if line == first and _block_matches(lines, i, block):
            return i
    return None


def apply_unified_diff(
    diff_text: str, base_dir: str | Path = ".", dry_run: bool = False
) -> ApplyResult:
    """Apply a unified diff under ``base_dir``. Returns an ApplyResult.

    ``dry_run=True`` validates that every hunk would apply cleanly without
    modifying any files.
    """
    base = Path(base_dir)
    file_diffs = parse_unified_diff(diff_text)
    if not file_diffs:
        return ApplyResult(
            success=False, message="No parseable unified diff hunks found.", rejected_hunks=0
        )

    base_resolved = base.resolve()
    changed: list[str] = []
    rejected = 0

    for fd in file_diffs:
        target = base / fd.target_path
        # Guard against crafted diffs escaping the repository root
        # (e.g. ``+++ b/../../etc/cron.d/x``) via ``..`` or symlinks.
        try:
            target_resolved = target.resolve()
        except OSError:
            rejected += 1
            continue
        if target_resolved != base_resolved and base_resolved not in target_resolved.parents:
            rejected += 1
            continue
        if not target.exists():
            rejected += 1
            continue
        try:
            # newline="" keeps \r\n intact so CRLF files stay CRLF.
            with open(target, encoding="utf-8", newline="") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            rejected += 1
            continue

        lines = content.splitlines()
        # Track whether the file ends with a newline and its line-ending style
        # so we can preserve them.
        ends_with_newline = content.endswith("\n") if content else True
        crlf = "\r\n" in content
        newline = "\r\n" if crlf else "\n"

        result_lines = list(lines)
        ok = True

        # Apply hunks bottom-up: each hunk's old_start refers to the ORIGINAL
        # file numbering, and edits above a hunk never shift the regions below
        # it — this keeps pure-addition hunks (no context to fuzzy-match)
        # positioned correctly after earlier hunks changed line counts.
        for hunk in reversed(fd.hunks):
            pos = _find_hunk_position(result_lines, hunk)
            if pos is None:
                ok = False
                rejected += 1
                break

            # Replace the original block with the new (context + added) block.
            old_len = len(_original_block(hunk))
            new_block = [text for marker, text in hunk.lines if marker in (" ", "+")]
            result_lines = result_lines[:pos] + new_block + result_lines[pos + old_len :]

        if ok:
            new_content = newline.join(result_lines)
            if ends_with_newline:
                new_content += newline
            if not dry_run:
                with open(target, "w", encoding="utf-8", newline="") as fh:
                    fh.write(new_content)
            changed.append(fd.target_path)

    success = rejected == 0
    message = (
        f"Applied {len(changed)} file(s)."
        if success
        else f"Applied {len(changed)} file(s), {rejected} hunk(s) rejected."
    )
    if dry_run:
        message = (
            f"Dry run: {len(changed)} file(s) would be patched."
            if success
            else f"Dry run: {len(changed)} file(s) would be patched, {rejected} hunk(s) rejected."
        )
    return ApplyResult(
        success=success, message=message, changed_files=changed, rejected_hunks=rejected
    )


__all__ = ["ApplyResult", "FileDiff", "Hunk", "apply_unified_diff", "parse_unified_diff"]
