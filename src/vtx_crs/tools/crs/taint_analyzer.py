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
from vtx.coding_agent.tools import BaseTool

from vtx_crs.core import get_case_manager

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
        seen: set[tuple[str, str, str]] = set()

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

            for lineno, line in enumerate(lines, 1):
                sources = [k for k, pat in _SOURCE_PATTERNS.items() if pat.search(line)]
                sinks = [k for k, pat in _SINK_PATTERNS.items() if pat.search(line)]
                if not sources or not sinks:
                    continue

                key = (rel, ",".join(sorted(sources)), ",".join(sorted(sinks)))
                if key in seen:
                    continue
                seen.add(key)

                flows.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "sources": sources,
                        "sinks": sinks,
                        "code": line.strip()[:200],
                    }
                )
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

        result_text = "\n".join(lines_out)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(flows)} taint candidate(s)",
            ui_details=result_text,
        )
