"""Build a call-graph / import-dependency map from the repository source.

This is a heuristic, text-based call graph: it scans function definitions and
calls, then assembles a local call graph per file. It is not a full points-to
analysis, but it is enough to guide the model toward reachability reasoning.
"""

from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.coding_agent.tools import BaseTool

from vtx_crs.core import get_case_manager

from ._common import MAX_FILE_BYTES, iter_source_files, resolve_repo_path

_case_manager = get_case_manager()


class CallGraphParams(BaseModel):
    repo_path: str = ""
    max_depth: int = 3
    include_exts: list[str] = [".py", ".js", ".ts", ".go", ".rs", ".c", ".cpp"]


class CallGraphTool(BaseTool[CallGraphParams]):
    name = "call_graph"
    description = (
        "Build a heuristic call graph from the repository source. Returns a "
        "text/mermaid-style dependency map of function calls and imports so "
        "the model can reason about reachability and data flow."
    )
    params = CallGraphParams
    mutating = False
    prompt_guidelines = (
        "Run call_graph after repo_analyze to map entry points.",
        "Use it to find which functions can reach a suspicious sink before patching.",
        "Combine with taint_analyze to trace untrusted data flow.",
    )

    async def execute(
        self, params: CallGraphParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        depth = max(1, min(params.max_depth, 10))
        extensions = set(params.include_exts)

        lines: list[str] = [
            f"Call graph (max_depth={depth}) for {repo}",
            "",
        ]
        found = 0

        for path in iter_source_files(repo, extensions):
            if cancel_event and cancel_event.is_set():
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = path.relative_to(repo)
            ext = path.suffix.lower()

            if ext == ".py":
                found += self._python_graph(rel, content, lines, depth)
            else:
                found += self._regex_graph(rel, content, lines, depth)

        if not found:
            return ToolResult(
                success=True,
                result="No callable symbols found in the selected files.",
                ui_summary="Empty call graph",
                ui_details="",
            )

        result_text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"call_graph: {found} symbol(s) mapped",
            ui_details=result_text,
        )

    @staticmethod
    def _python_graph(rel: Path, content: str, out: list[str], depth: int) -> int:
        found = 0
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return 0

        funcs: dict[str, list[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls: list[str] = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        func = child.func
                        if isinstance(func, ast.Name):
                            calls.append(func.id)
                        elif isinstance(func, ast.Attribute):
                            calls.append(f"{func.value.id}.{func.attr}" if isinstance(func.value, ast.Name) else func.attr)
                funcs[node.name] = list(dict.fromkeys(calls))

        if not funcs:
            return 0

        out.append(f"## {rel}")
        for func, calls in funcs.items():
            out.append(f"- {func}()")
            for c in calls[:depth * 5]:
                out.append(f"  -> {c}()")
            found += 1
        out.append("")
        return found

    @staticmethod
    def _regex_graph(rel: Path, content: str, out: list[str], depth: int) -> int:
        found = 0
        defs = re.findall(r"(?:function|func|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", content)
        calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", content)
        if not defs:
            return 0
        out.append(f"## {rel}")
        for d in defs[:depth * 10]:
            out.append(f"- {d}()")
            found += 1
        out.append("")
        return found
