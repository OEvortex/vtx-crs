"""Validate a patch: syntax check, build, test, and optional security verification.

Applies the patch in a temporary context, then runs the project's build and
test commands. Optionally re-runs a validation command (e.g., a PoC) against
the patched code to prove the fix. Reports pass/fail and any output for triage.

Merged security_validate: pass `validation_command` to run a reproducer
after build+test and verify the fix.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import FindingStatus, VerificationStatus, get_case_manager

from ._common import resolve_repo_path
from .patch_apply import PatchApplyParams, PatchApplyTool

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class PatchValidateParams(BaseModel):
    repo_path: str = Field(default="", description="Project root path. Defaults to the active case repo.")
    patch_file: str = Field(
        default="",
        description="Path to the patch diff file OR raw unified diff text to validate.",
    )
    build_command: str = Field(
        default="python -m compileall -q .",
        description="Build command inside the sandbox (default: python -m compileall -q .).",
    )
    test_command: str = Field(default="", description="Regression test command inside the sandbox.")
    strict_tests: bool = Field(default=True, description="Fail validation if any unit test fails.")
    validation_command: str = Field(
        default="",
        description="Optional post-build/test validation command (e.g., re-run PoC) to prove the fix.",
    )
    expected_validation_exit_code: int | None = Field(
        default=0, description="Expected exit code from validation_command. Defaults to 0."
    )
    finding_id: str = Field(default="", description="ID of the finding being validated.")


class PatchValidatorTool(BaseTool[PatchValidateParams]):
    name = "patch_validate"
    description = (
        "Applies a patch in an isolated temporary sandbox, then builds, runs regression tests, and optionally "
        "re-runs a validation command (e.g., PoC reproducer) to verify the fix. "
        "Call with patch_file (pointing to diff file or containing raw diff string) and optional validation_command."
    )
    params = PatchValidateParams
    mutating = True
    prompt_guidelines = (
        "Pass patch_file pointing to the diff file created on disk or pass raw diff content.",
        "Provide validation_command to re-test the PoC reproducer against the patched code.",
        "Always pass finding_id so verified findings are marked FIXED in the case ledger.",
    )

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

        patch_file_str = params.patch_file.strip()
        if not patch_file_str:
            return ToolResult(
                success=False,
                result="Empty patch_file parameter. Provide a path to a patch diff file or raw unified diff text.",
                ui_summary="Missing patch",
                ui_details="",
            )

        patch_path = Path(patch_file_str)
        if patch_path.is_file():
            try:
                diff_text = patch_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                return ToolResult(
                    success=False,
                    result=f"Failed to read patch file: {exc}",
                    ui_summary="Patch read failed",
                    ui_details="",
                )
        else:
            # Treat patch_file argument as the raw diff content itself
            diff_text = patch_file_str

        # Apply patch in a temporary copy so we don't pollute the case repo.
        with tempfile.TemporaryDirectory(prefix="vtx_crs_patch_") as tmp:
            work = Path(tmp)
            self._copy_tree(repo, work)
            apply_result = await PatchApplyTool().execute(
                PatchApplyParams(diff=diff_text, repo_path=str(work)),
                cancel_event=cancel_event,
            )
            if not apply_result.success:
                return apply_result

            build_code, build_out = await self._run_command(
                work, params.build_command, cancel_event
            )
            if build_code != 0:
                summary = f"Build failed (exit {build_code})"
                return ToolResult(
                    success=False,
                    result=f"Build failed.\n\n{build_out}",
                    ui_summary=summary,
                    ui_details="\n".join([summary, f"$ {params.build_command}", "", build_out]),
                )

            if not params.test_command:
                summary = "Build passed. No test_command configured."
                return ToolResult(
                    success=True,
                    result=summary,
                    ui_summary=summary,
                    ui_details="\n".join([summary, f"$ {params.build_command}", "", build_out]),
                )

            test_code, test_out = await self._run_command(
                work, params.test_command, cancel_event
            )
            passed = test_code == 0 or (not params.strict_tests)
            status = "passed" if passed else "failed"

            # Optional security validation (merged from security_validate)
            validation_passed = True
            validation_out = ""
            validation_summary = ""
            if params.validation_command:
                val_code, val_raw = await self._run_validation(
                    work, params.validation_command, cancel_event
                )
                expected = params.expected_validation_exit_code if params.expected_validation_exit_code is not None else 0
                validation_passed = val_code == expected
                validation_out = val_raw
                validation_summary = (
                    f"Validation {'PASSED' if validation_passed else 'FAILED'}: exit {val_code} "
                    f"(expected {expected})"
                )

            case = _case_manager.active_case
            if params.finding_id:
                finding = case.get_finding(params.finding_id)
                if finding is not None and validation_passed and params.validation_command:
                    case.update_finding_status(params.finding_id, FindingStatus.FIXED)
                for patch in case.patches.values():
                    if params.finding_id in patch.finding_ids:
                        patch.verification = (
                            VerificationStatus.PASSED if validation_passed else VerificationStatus.FAILED
                        )
                        patch.verified_at = datetime.now(UTC).isoformat()

            lines = [
                f"Patch validation {status}.",
                validation_summary if validation_summary else "",
                "",
                "Output:",
                f"$ {params.build_command}",
            ]
            lines.extend(build_out.strip().splitlines()[-15:])
            if test_out:
                lines.append("")
                lines.append(f"$ {params.test_command}")
                lines.extend(test_out.strip().splitlines()[-15:])
            if validation_out:
                lines.append("")
                lines.append(f"$ {params.validation_command}")
                lines.extend(validation_out.strip().splitlines()[-15:])

            if params.finding_id:
                label = "verified FIXED" if validation_passed else "still open"
                lines.append("")
                lines.append(f"Finding {params.finding_id} {label}.")

            result_text = "\n".join(lines)
            summary = f"Tests {status}" + (f", validation {status}" if params.validation_command else "")
            success = passed and (validation_passed if params.validation_command else True)

            if params.validation_command:
                case.record_validation({
                    "command": params.validation_command,
                    "exit_code": 0 if validation_passed else 1,
                    "duration_seconds": 0,
                    "expected_exit_code": params.expected_validation_exit_code,
                    "finding_id": params.finding_id,
                    "summary": validation_summary,
                    "details": validation_out[-8000:],
                })
                _case_manager.save_active()

            return ToolResult(
                success=success,
                result=result_text,
                ui_summary=summary,
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
                    target.symlink_to(child.readlink())
                elif child.is_dir():
                    shutil.copytree(child, target, symlinks=True, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".git"))
                else:
                    shutil.copy2(child, target)
            except OSError:
                try:
                    if child.is_file():
                        target.write_bytes(child.read_bytes())
                except OSError:
                    continue

    @staticmethod
    async def _run_command(repo: Path, command: str, cancel_event: asyncio.Event | None) -> tuple[int, str]:
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
        return proc.returncode, text

    @staticmethod
    async def _run_validation(repo: Path, command: str, cancel_event: asyncio.Event | None, timeout_seconds: int = 300) -> tuple[int, str]:
        import shlex

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(repo),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds
            )
            output = (stdout_bytes or b"").decode("utf-8", errors="replace")
            exit_code = proc.returncode
        except TimeoutError:
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.kill()
            output = f"Validation timed out after {timeout_seconds}s."
            exit_code = -1
        return exit_code, output
