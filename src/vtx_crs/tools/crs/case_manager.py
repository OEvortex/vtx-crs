"""Case management tool: create/switch/list/close CRS cases."""

from __future__ import annotations

import asyncio
from typing import Literal

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import get_case_manager

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class CaseManagerParams(BaseModel):
    action: Literal["create", "switch", "list", "summary", "note", "close"] = Field(
        default="summary",
        description="Case lifecycle operation: 'create' (new assessment) | 'switch' (activate case) | 'list' | 'summary' (view active ledger) | 'note' | 'close'."
    )
    title: str = Field(default="", description="Human-readable title for the case engagement.")
    repo_path: str = Field(default="", description="Root repository path attached to the case.")
    case_id: str = Field(default="", description="Target case ID for switch/close operations.")
    note: str = Field(default="", description="Audit note text to record in the case timeline.")


class CaseManagerTool(BaseTool[CaseManagerParams]):
    name = "case_manager"
    description = (
        "Case Lifecycle & State Ledger Manager: Tracks the entire audit session across reconnaissance, "
        "findings, patches, and validation proofs. Automatically persists state across sessions."
    )
    params = CaseManagerParams
    mutating = True
    prompt_guidelines = (
        "Initialize the case ledger at the start of an engagement using case_manager(action='create', ...).",
        "Call case_manager(action='summary') between phases to review current finding statuses.",
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

        # summary (default) — now detailed so user sees findings immediately
        s = case.summary()
        lines = [
            f"Case: {case.title} ({case.case_id})",
            f"Repo: {case.repo_path or 'unset'}",
            f"Status: {case.status}",
            f"Created: {case.created_at}",
            f"Updated: {case.updated_at}",
            "",
            f"Findings: {s['findings_count']}  (critical:{s['findings_by_severity']['critical']} high:{s['findings_by_severity']['high']} medium:{s['findings_by_severity']['medium']} low:{s['findings_by_severity']['low']} info:{s['findings_by_severity']['info']})",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"  {sev}: {s['findings_by_severity'][sev]}")
        lines.append(f"Patches: {s['patches_count']} ({s['patches_applied']} applied)")
        lines.append(f"Build exit: {s['build_exit'] if s['build_exit'] is not None else 'N/A'}")
        lines.append(f"Tests: {s['tests_passed'] or 0} passed / {s['tests_failed'] or 0} failed")

        # Detailed findings table (fixes "0 findings" confusion — show actual findings)
        if case.findings:
            lines.append("")
            lines.append(f"Findings detail ({len(case.findings)}):")
            lines.append(f"{'ID':<14} {'SEV':<9} {'CWE':<10} {'FILE:LINE':<32} TITLE")
            lines.append("-" * 90)
            # Sort by severity then file
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for f in sorted(case.findings.values(), key=lambda x: (order.get(x.severity.value, 9), x.file_path)):
                loc = f"{f.file_path}:{f.line_start}" if f.file_path else "-"
                sev = f.severity.value
                cwe = f.cwe_id or "-"
                title = f.title[:50]
                lines.append(f"{f.id:<14} {sev:<9} {cwe:<10} {loc:<32} {title}")
                if f.code_snippet:
                    snippet = f.code_snippet.strip().splitlines()[0][:80] if f.code_snippet.strip() else ""
                    if snippet:
                        lines.append(f"  ↳ {snippet}")
                if f.remediation:
                    lines.append(f"  fix: {f.remediation[:80]}")
        else:
            lines.append("")
            lines.append("No findings yet — run unified_scan (or vuln_scan/sast_scan) with save_findings=true, or dependency_scan. All tools auto-save to this case now.")

        if case.patches:
            lines.append("")
            lines.append(f"Patches ({len(case.patches)}):")
            for p in case.patches.values():
                lines.append(f"  {p.id} [{p.status.value}] {p.summary[:60]} -> {', '.join(p.changed_files[:3]) if p.changed_files else 'no files'}")

        lines.append("")
        lines.append(f"Timeline ({len(case.timeline)} events, last 8):")
        for event in case.timeline[-8:]:
            lines.append(f"  {event}")
        if case.notes:
            lines.append("")
            lines.append(f"Notes ({len(case.notes)}):")
            for n in case.notes[-3:]:
                lines.append(f"  {n}")
        lines.append("")
        lines.append(f"Storage: {_case_manager.storage_dir / (case.case_id + '.json')}")
        lines.append(f"Tip: generate_report writes {case.repo_path or '.'}/.vtx_crs/reports/{case.case_id}/report.md")
        text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=text,
            ui_summary=f"{s['findings_count']} findings, {s['patches_applied']} patches applied -> case {case.case_id}",
            ui_details=text,
        )
