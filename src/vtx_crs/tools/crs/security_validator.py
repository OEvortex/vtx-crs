"""Security validation tool: proves a fix by running a check/PoC command."""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime

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

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class SecurityValidateParams(BaseModel):
    repo_path: str = Field(default="", description="Project root path. Defaults to the active case repo.")
    command: str = Field(..., description="Validation command or PoC script to execute.")
    expected_exit_code: int | None = Field(default=None, description="Expected return code indicating successful mitigation.")
    finding_id: str = Field(default="", description="ID of the finding being validated.")
    note: str = Field(default="", description="Contextual note or proof explanation.")
    timeout_seconds: int = Field(default=300, description="Validation command timeout in seconds (default 300).")


class SecurityValidatorTool(BaseTool[SecurityValidateParams]):
    name = "security_validate"
    description = (
        "Re-runs a PoC or validation command against the patched codebase to prove a fix works. "
        "Use after patch_apply and patch_validate. Call with command set to the reproducer and finding_id for tracking."
    )
    params = SecurityValidateParams
    mutating = True
    prompt_guidelines = ()

    async def execute(
        self, params: SecurityValidateParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        started = time.monotonic()
        proc = None
        try:
            proc = await asyncio.create_subprocess_shell(
                params.command,
                cwd=str(repo),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=params.timeout_seconds
            )
            output = (stdout_bytes or b"").decode("utf-8", errors="replace")
            exit_code = proc.returncode
        except TimeoutError:
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.kill()
            output = f"Validation timed out after {params.timeout_seconds}s."
            exit_code = -1
        duration = round(time.monotonic() - started, 1)

        case = _case_manager.active_case
        if params.expected_exit_code is not None:
            success = exit_code == params.expected_exit_code
            summary = (
                f"Validation {'PASSED' if success else 'FAILED'}: exit {exit_code} "
                f"(expected {params.expected_exit_code}) in {duration}s"
            )
        else:
            success = exit_code == 0
            summary = f"Validation ran: exit {exit_code} in {duration}s"

        if params.finding_id:
            finding = case.get_finding(params.finding_id)
            verification = VerificationStatus.PASSED if success else VerificationStatus.FAILED
            if finding is not None:
                if success:
                    case.update_finding_status(params.finding_id, FindingStatus.FIXED)
                for patch in case.patches.values():
                    if params.finding_id in patch.finding_ids:
                        patch.verification = verification
                        patch.verified_at = datetime.now(UTC).isoformat()
                summary += f" Finding {params.finding_id} verified {'FIXED' if success else 'still open'}."

        case.record_validation(
            {
                "command": params.command,
                "exit_code": exit_code,
                "duration_seconds": duration,
                "expected_exit_code": params.expected_exit_code,
                "finding_id": params.finding_id,
                "summary": summary,
                "details": output[-8000:],
            }
        )
        _case_manager.save_active()

        tail = output.strip().splitlines()[-25:]
        detail_lines = [summary, f"$ {params.command}", ""]
        detail_lines.extend(tail)

        return ToolResult(
            success=success, result=summary, ui_summary=summary, ui_details="\n".join(detail_lines)
        )
