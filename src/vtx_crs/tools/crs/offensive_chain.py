"""Offensive chain: merged exploit proof workflow (OP).

Merges crash_triage + exploit_feasibility + pov_generate (+ optional dynamic_analyze/fuzz_target)
into one call — reduces offensive proof from 5 tool calls to 1.
Free hardening intel included; no keys.
"""

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
    from vtx.core.types import ToolResult  # type: ignore

from vtx_crs.core import get_case_manager
from ._common import resolve_repo_path

_case_manager = get_case_manager()


class OffensiveChainParams(BaseModel):
    repo_path: str = ""
    binary_path: str = ""
    crash_file: str = ""
    crash_text: str = ""
    vuln_type: str = ""
    generate_pov: bool = True
    pov_type: str = "python"


class OffensiveChainTool(BaseTool[OffensiveChainParams]):
    name = "offensive_chain"
    description = (
        "OP merged offensive proof: runs crash_triage -> exploit_feasibility (mitigation matrix) -> pov_generate "
        "in one call. Provide crash_file or crash_text + optional binary_path. Use instead of calling "
        "crash_triage, exploit_feasibility, and pov_generate separately — 3x faster. Free, no key."
    )
    params = OffensiveChainParams
    mutating = True
    prompt_guidelines = (
        "Use offensive_chain right after fuzz_target/dynamic_analyze finds a crash — it classifies, checks feasibility, and builds a PoC in one go.",
        "Provide binary_path for accurate hardening verdict (NX/PIE/RELRO/canary/FORTIFY).",
        "If vuln_type is known (e.g., buffer-overflow), pass it for precise chain_breaks.",
    )

    async def execute(self, params: OffensiveChainParams, cancel_event: asyncio.Event | None = None) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists():
            return ToolResult(success=False, result=f"Repo not found: {repo}", ui_summary="Invalid repo", ui_details="")

        from .crash_triager import CrashTriagerTool, CrashTriageParams
        from .exploit_feasibility import ExploitFeasibilityTool, ExploitFeasibilityParams
        from .pov_generator import PovGeneratorTool, PovGenerateParams

        crash_src = params.crash_file or params.crash_text
        if not crash_src:
            return ToolResult(success=False, result="Provide crash_file or crash_text", ui_summary="Missing crash", ui_details="")

        # 1) Crash triage
        triage = CrashTriagerTool()
        t_res = await triage.execute(CrashTriageParams(crash_file=params.crash_file, crash_text=params.crash_text, repo_path=str(repo)), cancel_event)

        # Extract vuln_type if not provided: try from triage result
        vuln_type = params.vuln_type
        if not vuln_type and t_res:
            # parse "Crash type:" line from ui_details
            detail = getattr(t_res, "ui_details", "") or getattr(t_res, "result", "")
            for line in detail.splitlines():
                if "Crash type" in line:
                    vuln_type = line.split(":", 1)[-1].strip().lower().replace(" ", "-")
                    break

        # 2) Exploit feasibility (needs binary + crash)
        feas = ExploitFeasibilityTool()
        f_res = await feas.execute(ExploitFeasibilityParams(
            repo_path=str(repo), binary_path=params.binary_path,
            crash_input=crash_src if not params.crash_file else "",
            crash_file=params.crash_file, vuln_type=vuln_type or params.vuln_type,
        ), cancel_event)

        # 3) PoV generation (only if feasible or generate_pov forced)
        pov_res = None
        if params.generate_pov:
            # Check verdict — skip if blocked, unless user forced
            verdict = ""
            if f_res:
                d = getattr(f_res, "ui_summary", "") or getattr(f_res, "result", "")
                import re
                m = re.search(r"Verdict:\s*(\w+)", d)
                verdict = m.group(1).lower() if m else ""
            if verdict != "blocked":
                pov = PovGeneratorTool()
                # try to infer target_file from crash
                target_file = ""
                if params.binary_path:
                    target_file = params.binary_path
                pov_res = await pov.execute(PovGenerateParams(
                    repo_path=str(repo), target_file=target_file,
                    crash_input=params.crash_text, crash_input_file=params.crash_file,
                    poc_type=params.pov_type,
                ), cancel_event)

        sections = [
            "## Offensive Chain (OP — crash -> feasibility -> PoC)",
            f"- Repo: {repo}",
            f"- Binary: {params.binary_path or '(auto-detect)'}",
            f"- Vuln type: {vuln_type or params.vuln_type or 'inferred'}",
            "",
            f"### 1) Crash Triage: {getattr(t_res, 'ui_summary', '') if t_res and not isinstance(t_res, Exception) else 'failed'}",
        ]
        if t_res and not isinstance(t_res, Exception):
            detail = getattr(t_res, "ui_details", "") or getattr(t_res, "result", "")
            sections.extend(f"  {l}" for l in detail.splitlines()[:20])
        sections.append("")
        sections.append(f"### 2) Exploit Feasibility: {getattr(f_res, 'ui_summary', '') if f_res and not isinstance(f_res, Exception) else 'failed'}")
        if f_res and not isinstance(f_res, Exception):
            detail = getattr(f_res, "ui_details", "") or getattr(f_res, "result", "")
            sections.extend(f"  {l}" for l in detail.splitlines()[:30])
        if pov_res and not isinstance(pov_res, Exception):
            sections.append("")
            sections.append(f"### 3) PoC: {getattr(pov_res, 'ui_summary', '')}")
            detail = getattr(pov_res, "ui_details", "") or getattr(pov_res, "result", "")
            sections.extend(f"  {l}" for l in detail.splitlines()[:20])
        elif params.generate_pov:
            sections.append("")
            sections.append("### 3) PoC: skipped (blocked verdict or error)")

        sections.extend([
            "",
            "### Next (defensive)",
            "- If feasibility is exploitable/likely: craft patch, then patch_apply -> patch_validate -> security_validate (re-run PoC must fail)",
            "- If blocked/constrained but crash is real: still patch (defense-in-depth) and harden via mitigation_inject",
        ])
        text = "\n".join(sections)
        success = bool(t_res and getattr(t_res, "success", False))
        return ToolResult(success=success, result=text, ui_summary=f"Chain: {getattr(t_res, 'ui_summary', '')} -> {getattr(f_res, 'ui_summary', '')}" if f_res else getattr(t_res, 'ui_summary', 'chain done'), ui_details=text)
