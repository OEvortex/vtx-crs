"""Report generator tool: writes the professional CRS report (MD + JSON)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

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
