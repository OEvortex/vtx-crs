"""Report generator tool: writes the professional CRS report (MD + JSON)."""

from __future__ import annotations

import asyncio
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

from vtx_crs.core import CrsReport, get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


class ReportGenParams(BaseModel):
    repo_path: str = ""
    output_dir: str = ""
    executive_summary: str = ""


class ReportGeneratorTool(BaseTool[ReportGenParams]):
    name = "generate_report"
    description = (
        "Generate the final professional security report (Markdown + JSON) from the active case: "
        "executive summary, scope & methodology, findings, patches, build/test results, security "
        "validation evidence, and conclusion. Returns the written file paths."
    )
    params = ReportGenParams
    mutating = True
    prompt_guidelines = (
        "Call generate_report as the final step of the pipeline, after validation.",
        "Write a short executive_summary describing the engagement outcome for the report.",
    )

    async def execute(
        self, params: ReportGenParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        case = _case_manager.active_case
        # If active case is empty (0 findings) but user previously scanned same repo in another case, auto-switch to that case so report is not empty
        # This fixes the ghost-case bug reported by user (new case 20260827_065110 vs old 20260827063304)
        _requested_repo = params.repo_path.strip() if params.repo_path else case.repo_path
        if _requested_repo:
            _req_path = str(Path(_requested_repo).expanduser().resolve()) if Path(_requested_repo).exists() else _requested_repo
            if not case.findings and _req_path:
                # Find the most recent case for this repo that actually has findings
                best = None
                best_time = ""
                for c in _case_manager._cases.values():
                    if c.repo_path and str(Path(c.repo_path).expanduser().resolve()) == _req_path and c.findings:
                        if not best or c.updated_at > best_time:
                            best = c
                            best_time = c.updated_at
                # Also check Storage files not yet loaded
                if not best:
                    _case_manager._load_all()
                    for c in _case_manager._cases.values():
                        if c.repo_path and str(Path(c.repo_path).expanduser().resolve()) == _req_path and c.findings:
                            if not best or c.updated_at > best_time:
                                best = c
                                best_time = c.updated_at
                if best:
                    _case_manager._active_case_id = best.case_id
                    try:
                        _case_manager._persist_active()
                    except Exception:
                        pass
                    case = best
        # Fallback: if still empty and no requested repo, pick latest case with findings at all
        if not case.findings:
            _case_manager._load_all()
            candidates = [c for c in _case_manager._cases.values() if c.findings]
            if candidates:
                best = max(candidates, key=lambda c: c.updated_at)
                if best.case_id != case.case_id:
                    _case_manager._active_case_id = best.case_id
                    try:
                        _case_manager._persist_active()
                    except Exception:
                        pass
                    case = best
        # Auto-attach repo to case if still unset
        if not case.repo_path and params.repo_path:
            _maybe = Path(params.repo_path).expanduser()
            if _maybe.exists():
                case.repo_path = str(_maybe.resolve())
                _case_manager.save_active()
        repo = resolve_repo_path(params.repo_path, case.repo_path)

        output_dir = params.output_dir.strip()
        if not output_dir:
            output_dir = str(repo / ".vtx_crs" / "reports" / case.case_id)
        out_path = Path(output_dir).expanduser()

        report = CrsReport(case, executive_summary=params.executive_summary.strip())
        written = report.write(out_path)

        summary = case.summary()
        lines = [
            f"Report generated for case {case.case_id} ({case.title}).",
            "",
            f"Findings: {summary['findings_count']} | "
            f"Patches applied: {summary['patches_applied']}/{summary['patches_count']} | "
            f"Tests: {summary['tests_passed'] or 0} passed / {summary['tests_failed'] or 0} failed | "
            f"Build exit: {summary['build_exit'] if summary['build_exit'] is not None else 'N/A'}",
            "",
            "Output:",
            f"  - Markdown: {written['markdown']}",
            f"  - JSON: {written['json']}",
        ]
        result_text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"Report written to {out_path}",
            ui_details=result_text,
        )
