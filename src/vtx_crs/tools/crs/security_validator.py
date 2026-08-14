"""Security validation tool: proves a fix by running a check/PoC command."""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import FindingStatus, VerificationStatus, get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


class SecurityValidateParams(BaseModel):
    repo_path: str = ""
    command: str
    expected_exit_code: int | None = None
    finding_id: str = ""
    note: str = ""
    timeout_seconds: int = 300


class SecurityValidatorTool(BaseTool[SecurityValidateParams]):
    name = "security_validate"
    description = (
        "Run a security validation step that proves a vulnerability is fixed: a PoC/exploit "
        "script that must fail after the patch, a targeted re-scan, or a check command. Compare "
        "the exit code to an expected value and record the verification in the case."
    )
    params = SecurityValidateParams
    mutating = True
    prompt_guidelines = (
        "After patching, run security_validate with a command that previously demonstrated the flaw — it must now fail.",
        "Pass the finding_id to attach the verification result to the finding and its patch.",
    )

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
