"""Regression test runner tool: discovers and runs the project's tests."""

from __future__ import annotations

import asyncio
import contextlib
import re
import time

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()

_SUMMARY_RE = re.compile(
    r"(?P<passed>\d+)\s+passed|(?P<failed>\d+)\s+failed|(?P<errors>\d+)\s+error", re.IGNORECASE
)


def detect_test_command(repo) -> str | None:
    if (repo / "pyproject.toml").exists():
        content = (repo / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
        if "[tool.pytest.ini_options]" in content:
            prefix = "uv run " if "[tool.uv]" in content or (repo / "uv.lock").exists() else ""
            return f"{prefix}python -m pytest -q"
    if (repo / "pytest.ini").exists() or (repo / "tox.ini").exists():
        return "python -m pytest -q"
    if (repo / "requirements-dev.txt").exists():
        content = (repo / "requirements-dev.txt").read_text(encoding="utf-8", errors="ignore")
        if "pytest" in content.lower():
            return "python -m pytest -q"
    if (repo / "Cargo.toml").exists():
        return "cargo test"
    if (repo / "package.json").exists():
        import json

        try:
            data = json.loads((repo / "package.json").read_text(encoding="utf-8"))
            script = (data.get("scripts") or {}).get("test")
            if script:
                return "npm test"
        except Exception:
            pass
    if list(repo.glob("**/*_test.go"))[:1]:
        return "go test ./..."
    for makefile in ("Makefile", "makefile"):
        if (repo / makefile).exists():
            content = (repo / makefile).read_text(encoding="utf-8", errors="ignore")
            if re.search(r"^test\s*:", content, re.MULTILINE):
                return "make test"
    return None


class TestRunParams(BaseModel):
    repo_path: str = ""
    command: str = ""
    timeout_seconds: int = 900


class TestRunnerTool(BaseTool[TestRunParams]):
    name = "run_tests"
    description = (
        "Run the project's regression test suite. Auto-detects the test command (pytest, cargo "
        "test, npm test, go test, make test) or accepts an explicit command. Summarizes "
        "passed/failed counts and exit code."
    )
    params = TestRunParams
    mutating = False
    prompt_guidelines = (
        "Run tests after a successful build. Any regression caused by a patch must be fixed before proceeding.",
        "Use the summary counts to prove regression status in the final report.",
    )

    async def execute(
        self, params: TestRunParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        command = params.command.strip() or detect_test_command(repo) or ""
        if not command:
            return ToolResult(
                success=False,
                result="Could not auto-detect a test command for this repository. Pass an explicit `command`.",
                ui_summary="No test command detected",
                ui_details="",
            )

        started = time.monotonic()
        proc = None
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(repo),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=params.timeout_seconds
            )
            output = (stdout_bytes or b"").decode("utf-8", errors="replace")
            exit_code = proc.returncode
            timed_out = False
        except TimeoutError:
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.kill()
            output = f"Tests timed out after {params.timeout_seconds}s."
            exit_code = -1
            timed_out = True
        duration = round(time.monotonic() - started, 1)

        # Extract individual totals from match groups.
        counts = {"passed": 0, "failed": 0, "errors": 0}
        for match in re.finditer(
            r"(?P<passed>\d+)\s+passed|(?P<failed>\d+)\s+failed|(?P<errors>\d+)\s+error",
            output,
            re.IGNORECASE,
        ):
            for key in counts:
                val = match.groupdict().get(key)
                if val:
                    counts[key] = int(val)

        failed = counts["failed"] + counts["errors"]
        total = sum(counts.values()) or 0
        success = exit_code == 0 and failed == 0

        result = {
            "command": command,
            "exit_code": exit_code,
            "duration_seconds": duration,
            "timed_out": timed_out,
            "passed": counts["passed"],
            "failed": failed,
            "total": total,
            "output": output[-8000:],
        }
        _case_manager.active_case.record_tests(result)
        _case_manager.save_active()

        summary = (
            f"Tests {'passed' if success else 'FAILED'}: {counts['passed']} passed, "
            f"{failed} failed (exit {exit_code}) in {duration}s"
        )
        tail = output.strip().splitlines()[-30:]
        detail_lines = [summary, f"$ {command}", ""]
        detail_lines.extend(tail)

        return ToolResult(
            success=success, result=summary, ui_summary=summary, ui_details="\n".join(detail_lines)
        )
