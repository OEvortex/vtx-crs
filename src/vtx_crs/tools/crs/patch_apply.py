"""Patch application tool: applies unified diffs with validation and tracking."""

from __future__ import annotations

import asyncio

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
    diff: str = Field(..., description="Unified diff formatted patch (--- / +++ / @@ hunks).")
    repo_path: str = Field(default="", description="Target repository root path.")
    finding_ids: list[str] = Field(default_factory=list, description="IDs of vulnerability findings resolved by this patch.")
    summary: str = Field(default="", description="Short explanation of the fix mechanism.")
    dry_run: bool = Field(default=False, description="If True, tests if patch applies cleanly without writing changes to disk.")


class PatchApplyTool(BaseTool[PatchApplyParams]):
    name = "patch_apply"
    description = (
        "Surgical Patch Application Engine (Phase 3): Applies unified diffs to the repository. "
        "Associates the patch with specific finding IDs and updates their status in the case ledger. "
        "Supports dry_run to verify diff context before committing."
    )
    params = PatchApplyParams
    mutating = True
    prompt_guidelines = ()

    async def execute(
        self, params: PatchApplyParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        if not params.diff.strip():
            return ToolResult(
                success=False,
                result="Empty diff. Provide a unified diff (--- / +++ / @@ hunks).",
                ui_summary="Empty diff",
                ui_details="",
            )

        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        result = apply_unified_diff(params.diff, base_dir=repo, dry_run=params.dry_run)

        case = _case_manager.active_case
        if not params.dry_run:
            patch = PatchRecord(
                diff=params.diff,
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
