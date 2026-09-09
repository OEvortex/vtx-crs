"""Patch application tool: applies unified diffs with validation and tracking."""

from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import (
    FindingStatus,
    PatchRecord,
    PatchStatus,
    apply_unified_diff,
    get_case_manager,
)

from ._common import resolve_repo_path

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class PatchApplyParams(BaseModel):
    diff: str = Field(
        ...,
        description=(
            "Unified diff string (with standard --- a/... +++ b/... @@ ... @@ headers) OR path to a patch file on disk. "
            "Pass the raw diff content directly or provide the file path."
        ),
    )
    repo_path: str = Field(
        default="",
        description="Absolute path to target repository root. If omitted, defaults to the active case repo.",
    )
    finding_ids: list[str] = Field(
        default_factory=list,
        description="List of case finding IDs (e.g. ['F-...']) that this patch resolves.",
    )
    summary: str = Field(
        default="",
        description="Short description of the fix (e.g. 'Fix SSRF by adding URL validation').",
    )
    dry_run: bool = Field(
        default=False,
        description="When True, checks if the patch applies cleanly without writing changes to disk.",
    )


class PatchApplyTool(BaseTool[PatchApplyParams]):
    name = "patch_apply"
    description = (
        "Applies a unified diff patch to the target codebase and records the patch in the case ledger. "
        "Supports standard unified diff format (--- a/file +++ b/file @@ ... @@) as raw diff text or a patch file path. "
        "Set dry_run=True to test whether the diff applies cleanly before writing changes, then dry_run=False to apply."
    )
    params = PatchApplyParams
    mutating = True
    prompt_guidelines = (
        "Pass the unified diff directly in the `diff` field using standard format (--- a/file, +++ b/file, @@ hunks) or give a path to a patch file.",
        "Ensure context lines match existing code in the target repository.",
        "Always pass finding_ids if fixing specific findings so their status updates in the case.",
        "Use dry_run=True first to verify the patch applies cleanly.",
    )

    async def execute(
        self, params: PatchApplyParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        diff_text = params.diff.strip()
        if not diff_text:
            return ToolResult(
                success=False,
                result="Empty diff. Provide a unified diff (--- / +++ / @@ hunks) or path to a patch file.",
                ui_summary="Empty diff",
                ui_details="",
            )

        # If agent passed a command like "cat /path/to/patch" or raw file path
        if diff_text.startswith("cat "):
            diff_text = diff_text[4:].strip().strip("'\"")
        potential_file = Path(diff_text)
        if potential_file.is_file():
            try:
                diff_text = potential_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass

        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        result = apply_unified_diff(diff_text, base_dir=repo, dry_run=params.dry_run)

        case = _case_manager.active_case
        if not params.dry_run:
            patch = PatchRecord(
                diff=diff_text,
                finding_ids=list(params.finding_ids),
                summary=params.summary or f"Patch {len(case.patches) + 1}",
                status=PatchStatus.APPLIED if result.success else PatchStatus.FAILED,
                changed_files=list(result.changed_files),
                apply_message=result.message,
            )
            if result.success:
                from datetime import UTC, datetime

                patch.applied_at = datetime.now(UTC).isoformat()
            case.add_patch(patch)

            if result.success:
                for fid in params.finding_ids:
                    case.update_finding_status(fid, FindingStatus.PATCHED)
            _case_manager.save_active()

            detail_lines = [result.message, "", "Changed files:"]
            detail_lines.extend(f"  - {f}" for f in (result.changed_files or ["(none)"]))
            detail_lines.append("")
            detail_lines.append(f"Patch ID: {patch.id} (status: {patch.status.value})")

            return ToolResult(
                success=result.success,
                result="\n".join(detail_lines),
                ui_summary=result.message,
                ui_details="\n".join(detail_lines),
            )

        detail_lines = [result.message, "", "Would change:"]
        detail_lines.extend(f"  - {f}" for f in (result.changed_files or ["(none)"]))
        return ToolResult(
            success=result.success,
            result="\n".join(detail_lines),
            ui_summary=result.message,
            ui_details="\n".join(detail_lines),
        )
