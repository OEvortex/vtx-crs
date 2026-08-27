"""Heuristic taint analysis: trace untrusted inputs to dangerous sinks.

This tool does not implement a full taint engine; instead it surfaces source
symbols (function parameters, env vars, request inputs) and sink symbols
(eval, exec, SQL, shell, file ops) so the model can reason about reachability.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import FindingStatus, Severity, VulnerabilityFinding, get_case_manager

from ._common import MAX_FILE_BYTES, iter_source_files, resolve_repo_path

_case_manager = get_case_manager()

_SOURCE_PATTERNS = {
    "request_input": re.compile(r"(?:request\.|req\.|http\.|params\.|query\.|body\.|input\.|POST|GET|argv|stdin|environ)", re.IGNORECASE),
    "file_input": re.compile(r"(?:open\(|read\(|load\(|import )", re.IGNORECASE),
    "env_input": re.compile(r"(?:os\.getenv|getenv|environ\[)", re.IGNORECASE),
    "network_input": re.compile(r"(?:socket|recv\(|read\(|urllib|requests\.|fetch\()", re.IGNORECASE),
}

_SINK_PATTERNS = {
    "eval_sink": re.compile(r"\b(?:eval|exec|compile|__import__|system|popen|subprocess)\s*\(", re.IGNORECASE),
    "sql_sink": re.compile(r"(?:execute\(|executemany\(|SELECT|INSERT|UPDATE|DELETE|query\()", re.IGNORECASE),
    "path_sink": re.compile(r"(?:open\(|os\.path|pathlib|join\(|write\()", re.IGNORECASE),
    "serialize_sink": re.compile(r"(?:pickle\.load|yaml\.load|json\.load|marshal\.load|loads\()", re.IGNORECASE),
}


class TaintAnalyzeParams(BaseModel):
    repo_path: str = ""
    max_findings: int = 50
    include_exts: list[str] = [".py", ".js", ".ts", ".c", ".cpp"]
    save_findings: bool = False  # taint is REVIEW by default; set True to persist to case for detailed report


class TaintAnalyzerTool(BaseTool[TaintAnalyzeParams]):
    name = "taint_analyze"
    description = (
        "Heuristic taint analysis: find untrusted input sources and trace them "
        "to dangerous sinks (eval, SQL, shell, file write, deserialization). "
        "Returns candidate taint flows for the model to confirm by code reading."
    )
    params = TaintAnalyzeParams
    mutating = False
    prompt_guidelines = (
        "Run taint_analyze after call_graph to prioritize reachable flows.",
        "Confirm each candidate flow by reading the actual code — do not patch blindly.",
        "Combine with vuln_scan to correlate pattern hits with taint reachability.",
    )

    async def execute(
        self, params: TaintAnalyzeParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        # Auto-attach repo to case if needed
        _tmp_case = _case_manager.active_case
        _tmp_repo = resolve_repo_path(params.repo_path, _tmp_case.repo_path)
        if _tmp_repo.exists() and not _tmp_case.repo_path:
            _tmp_case.repo_path = str(_tmp_repo)
            _case_manager.save_active()
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        extensions = set(params.include_exts)
        max_findings = max(1, min(params.max_findings, 200))
        flows: list[dict] = []
        seen: set[tuple[str, str, str, str]] = set()

        # Offensive+Defensive: file-level taint with variable propagation (RAPTOR-style heuristic)
        # 1) Collect source variables per file, then find sinks reachable via those vars
        for path in iter_source_files(repo, extensions):
            if cancel_event and cancel_event.is_set():
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = str(path.relative_to(repo))
            lines = content.splitlines()

            # Phase 1: find source lines and tainted variable names
            tainted_vars: set[str] = set()
            source_lines: list[tuple[int, str, list[str]]] = []
            var_assign_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*.*(?:request|req\.|input|argv|environ|socket|recv|urllib|requests\.|params|query|body)", re.IGNORECASE)
            for lineno, line in enumerate(lines, 1):
                srcs = [k for k, pat in _SOURCE_PATTERNS.items() if pat.search(line)]
                if srcs:
                    source_lines.append((lineno, line.strip()[:200], srcs))
                    m = var_assign_re.search(line)
                    if m:
                        tainted_vars.add(m.group(1))
                    # also mark generic taint if source is direct argument
                    if re.search(r"\b(?:request|argv|input)\b", line, re.IGNORECASE):
                        tainted_vars.add("input")
                        tainted_vars.add("data")
                        tainted_vars.add("user_input")

            # Phase 2: find sink lines reachable via tainted vars or same-file proximity
            for lineno, line in enumerate(lines, 1):
                sinks = [k for k, pat in _SINK_PATTERNS.items() if pat.search(line)]
                if not sinks:
                    continue
                # Heuristic: sink is tainted if (a) same line has source, (b) line mentions tainted var, (c) within 15 lines after a source
                sources_here = [k for k, pat in _SOURCE_PATTERNS.items() if pat.search(line)]
                near_source = any(abs(lineno - sl) <= 15 for sl, _, _ in source_lines)
                var_tainted = any(tv in line for tv in tainted_vars) if tainted_vars else False
                if not (sources_here or var_tainted or near_source):
                    # Still report high-confidence sinks (eval/exec/pickle) even without propagation — defensive
                    if not any(s in sinks for s in ("eval_sink", "serialize_sink")):
                        continue
                    sources_here = ["unsanitized_input"]

                all_sources = list({*sources_here, *(s for sl, _, s_list in source_lines for s in s_list if abs(lineno - sl) <= 20)})
                if not all_sources:
                    all_sources = ["tainted_var"] if var_tainted else ["heuristic"]

                key = (rel, ",".join(sorted(all_sources)), ",".join(sorted(sinks)), str(lineno))
                if key in seen:
                    continue
                seen.add(key)

                flows.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "sources": sorted(set(all_sources)),
                        "sinks": sinks,
                        "code": line.strip()[:200],
                    }
                )
                if len(flows) >= max_findings:
                    break
            if len(flows) >= max_findings:
                break

        if not flows:
            return ToolResult(
                success=True,
                result="No obvious taint candidate flows found.",
                ui_summary="No taint flows",
                ui_details="",
            )

        lines_out = [
            f"Taint analysis: {len(flows)} candidate flow(s)",
            "",
            f"{'FILE':<30} {'LINE':<6} {'SOURCES':<20} {'SINKS':<20}",
            "-" * 80,
        ]
        for f in flows:
            lines_out.append(
                f"{f['file']:<30} {f['line']:<6} {','.join(f['sources']):<20} {','.join(f['sinks']):<20}"
            )
            lines_out.append(f"    {f['code']}")

        # Persist taint flows as REVIEW findings if requested (so case_manager shows them for detailed report)
        if params.save_findings and flows:
            case = _case_manager.active_case
            for fl in flows:
                vf = VulnerabilityFinding(
                    title=f"Taint: {','.join(fl['sinks'])} via {','.join(fl['sources'])}",
                    description=f"Taint flow: sources {fl['sources']} -> sinks {fl['sinks']} at {fl['file']}:{fl['line']}. Confirm by reading code.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-20",
                    confidence=0.35,
                    file_path=fl["file"],
                    line_start=fl["line"],
                    line_end=fl["line"],
                    code_snippet=fl["code"],
                    remediation="Validate flow; add allowlist/escaping/parameterization between source and sink.",
                    status=FindingStatus.REVIEW,
                    source="taint",
                    metadata={"sources": fl["sources"], "sinks": fl["sinks"]},
                )
                case.add_finding(vf)
            _case_manager.save_active()

        result_text = "\n".join(lines_out)
        persisted_note = f" -> case { _case_manager.active_case.case_id}" if params.save_findings and flows else ""
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(flows)} taint candidate(s){persisted_note}",
            ui_details=result_text,
        )
