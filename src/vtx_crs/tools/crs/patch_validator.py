"""Validate a patch: syntax check, build, and test.

Applies the patch in a temporary context, then runs the project's build and
test commands. Reports pass/fail and any output for triage.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import get_case_manager

from ._common import resolve_repo_path
from .patch_apply import PatchApplyParams, PatchApplyTool

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class PatchValidateParams(BaseModel):
    repo_path: str = Field(default="", description="Project root path. Defaults to the active case repo.")
    patch_file: str = Field(default="", description="Path to the patch diff file to validate.")
    build_command: str = Field(default="python -m compileall -q .", description="Build command inside the sandbox (default: python -m compileall -q .).")
    test_command: str = Field(default="", description="Regression test command inside the sandbox.")
    strict_tests: bool = Field(default=True, description="Fail validation if any unit test fails.")


class PatchValidatorTool(BaseTool[PatchValidateParams]):
    name = "patch_validate"
    description = (
        "Applies a patch in an isolated temp copy, then builds and runs tests to verify no regressions. "
        "Use after patch_apply to validate fixes. Call with patch_file pointing to the diff."
    )
    params = PatchValidateParams
    mutating = True
    prompt_guidelines = ()

    async def execute(
        self, params: PatchValidateParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        patch_path = Path(params.patch_file)
        if not patch_path.exists():
            return ToolResult(
                success=False,
                result=f"Patch file does not exist: {patch_path}",
                ui_summary="Missing patch",
                ui_details="",
            )

        # Apply patch in a temporary copy so we don't pollute the case repo.
        with tempfile.TemporaryDirectory(prefix="vtx_crs_patch_") as tmp:
            work = Path(tmp)
            self._copy_tree(repo, work)
            try:
                diff_text = patch_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                return ToolResult(
                    success=False,
                    result=f"Failed to read patch file: {exc}",
                    ui_summary="Patch read failed",
                    ui_details="",
                )
            apply_result = await PatchApplyTool().execute(
                PatchApplyParams(diff=diff_text, repo_path=str(work)),
                cancel_event=cancel_event,
            )
            if not apply_result.success:
                return apply_result

            build_ok, build_out = await self._run_command(
                work, params.build_command, cancel_event
            )
            if not build_ok:
                return ToolResult(
                    success=False,
                    result=f"Build failed.\n\n{build_out}",
                    ui_summary="Build failed",
                    ui_details=build_out,
                )

            if not params.test_command:
                return ToolResult(
                    success=True,
                    result="Build passed. No test_command configured.",
                    ui_summary="Build passed, no tests",
                    ui_details="",
                )

            test_ok, test_out = await self._run_command(
                work, params.test_command, cancel_event
            )
            passed = test_ok or (not params.strict_tests)
            status = "passed" if passed else "failed"
            result_text = (
                f"Patch validation {status}.\n\n"
                f"Build output:\n{build_out}\n\n"
                f"Test output:\n{test_out}"
            )
            return ToolResult(
                success=passed,
                result=result_text,
                ui_summary=f"Tests {status}",
                ui_details=result_text,
            )

    @staticmethod
    def _copy_tree(src: Path, dst: Path) -> None:
        import shutil

        dst.mkdir(parents=True, exist_ok=True)
        for child in src.iterdir():
            if child.name in (".venv", "__pycache__", ".git", ".hg", "node_modules", ".pytest_cache", ".ruff_cache", ".vtx", ".vtx_crs"):
                continue
            target = dst / child.name
            try:
                if child.is_symlink():
                    # Preserve symlink
                    target.symlink_to(child.readlink())
                elif child.is_dir():
                    shutil.copytree(child, target, symlinks=True, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".git"))
                else:
                    shutil.copy2(child, target)
            except OSError:
                # Fallback to bytes copy
                try:
                    if child.is_file():
                        target.write_bytes(child.read_bytes())
                except OSError:
                    continue

    @staticmethod
    async def _run_command(repo: Path, command: str, cancel_event: asyncio.Event | None) -> tuple[bool, str]:
        import shlex

        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(repo),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out = b""
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(4096)
            if not chunk:
                break
            out += chunk
            if cancel_event and cancel_event.is_set():
                proc.kill()
                break

        await proc.wait()
        text = out.decode("utf-8", errors="replace")
        return proc.returncode == 0, text
