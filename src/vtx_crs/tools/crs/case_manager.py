"""Case management tool: create/switch/list/close CRS cases."""

from __future__ import annotations

import asyncio
from typing import Literal

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import get_case_manager

_case_manager = get_case_manager()


class CaseManagerParams(BaseModel):
    action: Literal["create", "switch", "list", "summary", "note", "close"] = "summary"
    title: str = ""
    repo_path: str = ""
    case_id: str = ""
    note: str = ""


class CaseManagerTool(BaseTool[CaseManagerParams]):
    name = "case_manager"
    description = (
        "Manage CRS cases: create a case for a repository analysis, switch between cases, list "
        "existing cases, add notes, view a summary, or close the active case. Findings, patches, "
        "and validation results accumulate in the active case."
    )
    params = CaseManagerParams
    mutating = True
    prompt_guidelines = (
        "Create a case (with the target repo_path) at the start of an engagement.",
        "Use summary after each pipeline step to track progress.",
    )

    async def execute(
        self, params: CaseManagerParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        if params.action == "create":
            case = _case_manager.create_case(title=params.title, repo_path=params.repo_path)
            text = (
                f"Created case {case.case_id}: {case.title}\n"
                f"Repo: {case.repo_path or 'unset'} (use case_manager switch to return to it)"
            )
            return ToolResult(
                success=True, result=text, ui_summary=f"Case {case.case_id}", ui_details=text
            )

        if params.action == "switch":
            if not params.case_id:
                return ToolResult(
                    success=False,
                    result="case_id required",
                    ui_summary="Missing case_id",
                    ui_details="",
                )
            case = _case_manager.switch_case(params.case_id)
            if case is None:
                return ToolResult(
                    success=False,
                    result=f"Case {params.case_id} not found",
                    ui_summary="Not found",
                    ui_details="",
                )
            text = f"Switched to case {case.case_id}: {case.title} (repo: {case.repo_path or 'unset'})"
            return ToolResult(
                success=True, result=text, ui_summary=f"Case {case.case_id}", ui_details=text
            )

        if params.action == "list":
            cases = _case_manager.list_cases()
            if not cases:
                return ToolResult(
                    success=False,
                    result="No cases yet. Create one with action=create.",
                    ui_summary="No cases",
                    ui_details="",
                )
            lines = [f"{len(cases)} case(s):", ""]
            for c in cases:
                lines.append(
                    f"  {c['case_id']}  {c['status']:<6} {c['findings_count']} findings  {c['title']}"
                )
            text = "\n".join(lines)
            return ToolResult(
                success=True, result=text, ui_summary=f"{len(cases)} cases", ui_details=text
            )

        case = _case_manager.active_case
        if params.action == "note":
            if not params.note.strip():
                return ToolResult(
                    success=False,
                    result="note text required",
                    ui_summary="Empty note",
                    ui_details="",
                )
            case.add_note(params.note.strip())
            _case_manager.save_active()
            text = f"Note added to case {case.case_id}."
            return ToolResult(success=True, result=text, ui_summary="Note added", ui_details=text)

        if params.action == "close":
            case.close()
            _case_manager.save_active()
            text = f"Case {case.case_id} closed."
            return ToolResult(success=True, result=text, ui_summary="Case closed", ui_details=text)

        # summary (default)
        s = case.summary()
        lines = [
            f"Case: {case.title} ({case.case_id})",
            f"Repo: {case.repo_path or 'unset'}",
            f"Status: {case.status}",
            f"Created: {case.created_at}",
            "",
            f"Findings: {s['findings_count']}",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"  {sev}: {s['findings_by_severity'][sev]}")
        lines.append(f"Patches: {s['patches_count']} ({s['patches_applied']} applied)")
        lines.append(f"Build exit: {s['build_exit'] if s['build_exit'] is not None else 'N/A'}")
        lines.append(f"Tests: {s['tests_passed'] or 0} passed / {s['tests_failed'] or 0} failed")
        lines.append("")
        lines.append(f"Timeline ({len(case.timeline)} events):")
        for event in case.timeline[-8:]:
            lines.append(f"  {event}")
        text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=text,
            ui_summary=f"{s['findings_count']} findings, {s['patches_applied']} patches applied",
            ui_details=text,
        )
