"""Build runner tool: discovers and runs the project's build command."""

from __future__ import annotations

import asyncio
import contextlib
import time

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


def detect_build_command(repo) -> str | None:
    """Return a sensible build/install command for the repo, or None."""
    if (repo / "pyproject.toml").exists():
        if (repo / "uv.lock").exists() or (repo / "pyproject.toml").read_text(
            encoding="utf-8", errors="ignore"
        ).find("[tool.uv]") != -1:
            return "uv run python -m pip install -e ."
        return "python -m pip install -e ."
    if (repo / "setup.py").exists() or (repo / "setup.cfg").exists():
        return "python -m pip install -e ."
    if (repo / "Cargo.toml").exists():
        return "cargo build"
    if (repo / "package.json").exists():
        return "npm install && npm run build" if _has_build_script(repo) else "npm install"
    if (repo / "go.mod").exists():
        return "go build ./..."
    if (repo / "CMakeLists.txt").exists():
        return "cmake -S . -B build && cmake --build build"
    if (repo / "Makefile").exists() or (repo / "makefile").exists():
        return "make"
    return None


def _has_build_script(repo) -> bool:
    import json

    try:
        data = json.loads((repo / "package.json").read_text(encoding="utf-8"))
        return bool((data.get("scripts") or {}).get("build"))
    except Exception:
        return False


class BuildParams(BaseModel):
    repo_path: str = ""
    command: str = ""
    timeout_seconds: int = 600


class BuildRunnerTool(BaseTool[BuildParams]):
    name = "build_project"
    description = (
        "Build/install the software in the repository. Auto-detects the build command from the "
        "project type (pyproject.toml, Cargo.toml, package.json, go.mod, CMake, Makefile) or "
        "accepts an explicit command. Captures exit code and output."
    )
    params = BuildParams
    mutating = True
    prompt_guidelines = (
        "Run build_project after applying patches and before running tests.",
        "If the build fails, read the output, fix the cause, and re-run.",
    )

    async def execute(
        self, params: BuildParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        command = params.command.strip() or detect_build_command(repo) or ""
        if not command:
            return ToolResult(
                success=False,
                result="Could not auto-detect a build command for this repository. Pass an explicit `command`.",
                ui_summary="No build command detected",
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
            output = f"Build timed out after {params.timeout_seconds}s."
            exit_code = -1
            timed_out = True
        duration = round(time.monotonic() - started, 1)

        success = exit_code == 0
        result = {
            "command": command,
            "exit_code": exit_code,
            "duration_seconds": duration,
            "timed_out": timed_out,
            "output": output[-8000:],
        }
        _case_manager.active_case.record_build(result)
        _case_manager.save_active()

        status = "passed" if success else "failed"
        summary = f"Build {status} in {duration}s (exit {exit_code})"
        tail = output.strip().splitlines()[-25:]
        detail_lines = [summary, f"$ {command}", ""]
        detail_lines.extend(tail)

        return ToolResult(
            success=success, result=summary, ui_summary=summary, ui_details="\n".join(detail_lines)
        )
