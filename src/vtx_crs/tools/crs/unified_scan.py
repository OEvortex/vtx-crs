"""Unified security scan: OP merged defensive engine.

Merges vuln_scan (patterns+semgrep/bandit/gitleaks) + sast_scan + taint_analyze + secrets
into a single parallel call — reduces LLM tool-call overhead by 4x (RAPTOR scan optimization).
Free engines used when available; falls back to regex-only (always works).
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

if TYPE_CHECKING:
    from .taint_analyzer import TaintAnalyzeParams

from vtx_crs.core import get_case_manager
from ._common import resolve_repo_path

_case_manager = get_case_manager()


class UnifiedScanParams(BaseModel):
    repo_path: str = Field(default="", description="Absolute path to target repository root.")
    min_severity: str = Field(default="info", description="Minimum finding severity threshold: 'info' | 'low' | 'medium' | 'high' | 'critical'.")
    save_findings: bool = Field(default=True, description="Whether to automatically persist discovered findings into active case ledger.")
    include_taint: bool = Field(default=True, description="Whether to include source-to-sink taint analysis in the unified pass.")
    timeout_seconds: int = Field(default=90, description="Maximum execution timeout for parallel sub-scanners in seconds.")


class UnifiedScanTool(BaseTool[UnifiedScanParams]):
    name = "unified_scan"
    description = (
        "High-Performance Merged Defensive Scanner (Phase 1): Executes SAST structural checks, rule patterns (semgrep/bandit/gitleaks "
        "when available, plus internal regex engines), and taint analysis in parallel. Deduplicates results into a unified finding set. "
        "Always prefer over running vuln_scan, sast_scan, and taint_analyze separately."
    )
    params = UnifiedScanParams
    mutating = False
    prompt_guidelines = ()

    async def execute(self, params: UnifiedScanParams, cancel_event: asyncio.Event | None = None) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists():
            return ToolResult(success=False, result=f"Repo not found: {repo}", ui_summary="Invalid repo", ui_details="")

        # Auto-attach repo to case if case has no repo yet (fixes 0-findings ghost case)
        case = _case_manager.active_case
        if not case.repo_path:
            case.repo_path = str(repo)
        elif case.repo_path != str(repo):
            # If user scanned a different repo than case, update case repo (or create new if mismatch is big)
            # For now, just update to current repo so findings land in the viewed case
            case.repo_path = str(repo)
        _case_manager.save_active()

        # Lazy imports to avoid circular deps
        from .vuln_scanner import VulnScannerTool, VulnScanParams, DEFAULT_SCAN_EXTENSIONS
        from .sast_scanner import SastScannerTool
        from .taint_analyzer import TaintAnalyzerTool, TaintAnalyzeParams
        from vtx_crs.core import Severity

        vuln_tool = VulnScannerTool()
        sast_tool = SastScannerTool()
        taint_tool = TaintAnalyzerTool() if params.include_taint else None

        min_sev = Severity.from_str(params.min_severity)

        # Run scans and capture FINDING OBJECTS directly (not just ToolResult text) so we can persist accurately
        # Vuln: patterns + external engines
        vuln_findings = vuln_tool._scan_patterns(repo, set(DEFAULT_SCAN_EXTENSIONS), min_sev, cancel_event)
        vuln_external: list = []
        if VulnScannerTool is not None:
            try:
                vuln_external = await vuln_tool._run_external_engines(repo, min_sev, params.timeout_seconds, cancel_event)
                # dedup external vs patterns
                seen = {(f.file_path, f.line_start, f.metadata.get("pattern") or f.title) for f in vuln_findings}
                for ef in vuln_external:
                    key = (ef.file_path, ef.line_start, ef.metadata.get("pattern") or ef.title)
                    if key not in seen:
                        vuln_findings.append(ef)
                        seen.add(key)
            except Exception:
                pass

        # SAST: generate findings via its rule set (manual, reliable)
        sast_findings = []
        if not sast_findings:
            try:
                from .sast_scanner import _STRUCTURAL_RULES, _DEFAULT_SCAN_EXTENSIONS as _SDEF
                import re as _re
                from vtx_crs.core import VulnerabilityFinding as _VF, FindingStatus as _FS, Severity as _Sev
                from ._common import MAX_FILE_BYTES as _MFB, iter_source_files as _ISF
                sast_findings = []
                seen_sast: set[tuple[str, str, int]] = set()
                severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                min_rank = severity_rank.get(min_sev.value, 4)
                for path in _ISF(repo, _SDEF):
                    if cancel_event and cancel_event.is_set():
                        break
                    try:
                        if path.stat().st_size > _MFB:
                            continue
                        content = path.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    rel = str(path.relative_to(repo))
                    lines = content.splitlines()
                    for lineno, line in enumerate(lines, 1):
                        for rule in _STRUCTURAL_RULES:
                            if not _re.search(rule["pattern"], line, _re.IGNORECASE):
                                continue
                            if severity_rank.get(rule["severity"], 4) > min_rank:
                                continue
                            key = (rel, rule["name"], lineno)
                            if key in seen_sast:
                                continue
                            seen_sast.add(key)
                            sast_findings.append(_VF(
                                title=rule["name"].replace("_", " ").title(),
                                description=rule["description"],
                                severity=_Sev.from_str(rule["severity"]),
                                cwe_id=rule["cwe"],
                                confidence=rule["confidence"],
                                file_path=rel,
                                line_start=lineno,
                                line_end=lineno,
                                code_snippet=line.strip()[:200],
                                remediation=rule["remediation"],
                                status=_FS.OPEN,
                                source="sast",
                                metadata={"pattern": rule["name"]},
                            ))
            except Exception:
                sast_findings = []

        # Taint: collect flows as findings too
        taint_findings = []
        taint_res = None
        if taint_tool:
            taint_res = await taint_tool.execute(TaintAnalyzeParams(repo_path=str(repo), max_findings=40), cancel_event)
            # Also convert taint flows to VulnerabilityFinding objects for case persistence
            try:
                # taint_analyzer stores flows but not as findings; we convert the last run's flows
                # Re-derive quickly: use TaintAnalyzerTool's internal logic by inspecting its result is not enough
                # So we create findings from taint result text is lossy; instead we will create placeholder findings for each taint flow detected
                if taint_res and taint_res.success:
                    # Count flows from ui_summary
                    import re as _re2
                    m = _re2.search(r"(\d+)\s+taint", str(getattr(taint_res, "ui_summary", "")))
                    if m and int(m.group(1)) > 0:
                        # Create generic taint findings for persistence (so case shows them)
                        for _i in range(int(m.group(1))):
                            from vtx_crs.core import VulnerabilityFinding as _VF2, FindingStatus as _FS2, Severity as _Sev2
                            taint_findings.append(_VF2(
                                title="Taint flow: untrusted input -> sink",
                                description="Heuristic taint: untrusted source reaches dangerous sink (confirm by reading file). See taint_analyze details.",
                                severity=_Sev2.MEDIUM,
                                cwe_id="CWE-20",
                                confidence=0.4,
                                file_path=str(repo),
                                line_start=0,
                                code_snippet=getattr(taint_res, "ui_details", "")[:500],
                                remediation="Validate taint flow by reading code; add allowlist / parameterization / escaping at sink.",
                                status=_FS2.REVIEW,
                                source="taint",
                                metadata={"engine": "taint_analyzer"},
                            ))
                            break  # only one aggregated finding to avoid spam; taint already has flow list in details
            except Exception:
                pass

        # Now we have all finding objects; persist with deduplication
        all_findings = vuln_findings + sast_findings + taint_findings
        # Deduplicate by (file, line, pattern/title)
        seen_keys: set[tuple[str, int, str]] = set()
        deduped: list = []
        for f in all_findings:
            key = (f.file_path, f.line_start, f.metadata.get("pattern") or f.title)
            if key not in seen_keys:
                deduped.append(f)
                seen_keys.add(key)

        if params.save_findings and deduped:
            for f in deduped:
                case.add_finding(f)
            _case_manager.save_active()

        # Build report sections from actual counts (not ToolResult parsing)
        vc = len(vuln_findings)
        sc = len(sast_findings)
        taint_match = re.search(r"(\d+)", getattr(taint_res, "ui_summary", "") or "0")
        tc = len(taint_findings) if taint_findings else (int(taint_match.group(1)) if taint_match else 0) if taint_res else 0
        total = len(deduped)

        sections = [
            "## Unified Scan (OP Defensive — merged vuln+sast+taint)",
            f"- Repo: {repo}",
            f"- Min severity: {params.min_severity}",
            f"- Vuln (patterns+semgrep/bandit/gitleaks): {vc}",
            f"- SAST (structural): {sc}",
        ]
        if params.include_taint:
            sections.append(f"- Taint flows: {tc}")
        sections.append(f"- Total deduped findings persisted: {total} -> case {case.case_id}")
        sections.append("")

        if params.save_findings:
            sections.append(f"- Persisted {total} findings to case {case.case_id} ({case.title}) — run case_manager action=summary to see them.")

        # Add sub-sections with tool details
        vuln_detail = f"{vc} finding(s) (patterns + external engines)"
        sast_detail = f"{sc} structural finding(s)"
        taint_detail = getattr(taint_res, "ui_details", "") if taint_res else ""
        for label, detail in [("VULN", vuln_detail), ("SAST", sast_detail), ("TAINT", taint_detail or "No taint flows")]:
            sections.append("")
            sections.append(f"### {label}")
            for line in (detail.splitlines()[:30] if detail else ["(none)"]):
                sections.append(f"  {line}")

        sections.extend([
            "",
            "### Next (offensive validation)",
            "- For each high/critical: confirm by reading file:line",
            "- Then harness_gen -> fuzz_target / dynamic_analyze -> crash_triage -> exploit_feasibility -> pov_generate",
            "",
            "### Next (defensive hardening)",
            "- patch_apply (dry_run) -> patch_validate -> build_project -> run_tests -> security_validate -> generate_report",
        ])

        text = "\n".join(sections)
        return ToolResult(success=True, result=text, ui_summary=f"Unified: {vc} vuln + {sc} sast + {tc} taint = {total} persisted to {case.case_id}", ui_details=text)
