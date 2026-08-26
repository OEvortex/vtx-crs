"""Code coverage gap analysis.

If a coverage report is available, this tool parses it and surfaces uncovered
lines / functions. If not, it inspects the test command and build artifacts to
suggest how to obtain coverage.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.coding_agent.tools import BaseTool

from vtx_crs.core import get_case_manager

from ._common import MAX_FILE_BYTES, iter_source_files, resolve_repo_path

_case_manager = get_case_manager()


class CoverageAnalyzeParams(BaseModel):
    repo_path: str = ""
    coverage_file: str = ""
    test_command: str = "pytest --cov --cov-report=term-missing"
    include_exts: list[str] = [".py", ".js", ".ts", ".go", ".rs"]


class CoverageAnalyzerTool(BaseTool[CoverageAnalyzeParams]):
    name = "coverage_analyze"
    description = (
        "Analyze code coverage to find untested lines, functions, and files. "
        "If a coverage report is provided, it is parsed directly. Otherwise, "
        "the tool suggests how to generate a coverage report for the project."
    )
    params = CoverageAnalyzeParams
    mutating = False
    prompt_guidelines = (
        "Run coverage_analyze after build and test_runner pass.",
        "Use results to prioritize writing PoC harnesses and tests for uncovered sinks.",
        "If the project has no coverage tooling configured, the tool returns setup guidance.",
    )

    async def execute(
        self, params: CoverageAnalyzeParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        cov_path = Path(params.coverage_file) if params.coverage_file else repo / ".coverage"
        if cov_path.exists():
            return self._parse_existing_coverage(repo, cov_path, params.include_exts)

        return self._suggest_coverage_setup(repo, params.test_command)

    def _parse_existing_coverage(
        self, repo: Path, cov_path: Path, include_exts: list[str]
    ) -> ToolResult:
        # Try JSON coverage (pytest-cov json) or term-missing text fallback.
        summary = [
            f"Coverage report detected at: {cov_path}",
            "",
        ]
        gaps: list[tuple[str, str, int]] = []

        try:
            if cov_path.suffix == ".json":
                data = json.loads(cov_path.read_text(encoding="utf-8", errors="ignore"))
                for file_path, info in data.get("files", {}).items():
                    summary.append(f"{file_path}: {info.get('summary', {})}")
                    missing = info.get("missing_lines", info.get("missing_branches", []))
                    if missing:
                        gaps.append((file_path, "lines", len(missing)))
            else:
                text = cov_path.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(
                    r"(?P<path>\S+)\s+(?P<pct>\d+)%\s+(?P<miss>\d+)",
                    text,
                ):
                    gaps.append((m.group("path"), "lines", int(m.group("miss"))))
        except (OSError, json.JSONDecodeError):
            return ToolResult(
                success=True,
                result="Coverage file present but could not be parsed. See guidance in ui_details.",
                ui_summary="Unparseable coverage",
                ui_details="\n".join(summary + ["", "Run the test command with --cov-report=term-missing or json."]),
            )

        if not gaps:
            return ToolResult(
                success=True,
                result="No coverage gaps detected in the parsed report.",
                ui_summary="Full coverage",
                ui_details="",
            )

        gaps.sort(key=lambda x: x[2], reverse=True)
        summary += [
            "Largest coverage gaps:",
            f"{'PATH':<40} {'TYPE':<8} {'MISSING'}",
            "-" * 60,
        ]
        for path, typ, count in gaps[:20]:
            summary.append(f"{path:<40} {typ:<8} {count}")

        result_text = "\n".join(summary)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(gaps)} coverage gap(s)",
            ui_details=result_text,
        )

    def _suggest_coverage_setup(self, repo: Path, test_command: str) -> ToolResult:
        guidance = [
            "No existing coverage report found.",
            "",
            "Suggested commands to generate one:",
            "",
            f"  {test_command}",
            "",
            "If the project uses cargo (Rust):",
            "  cargo tarpaulin --out Html",
            "",
            "If the project uses go test:",
            "  go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out",
            "",
            "After generating the report, re-run coverage_analyze.",
        ]
        result_text = "\n".join(guidance)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary="No coverage report",
            ui_details=result_text,
        )
