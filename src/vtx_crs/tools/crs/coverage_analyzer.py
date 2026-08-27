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
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import get_case_manager

from ._common import MAX_FILE_BYTES, iter_source_files, resolve_repo_path

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class CoverageAnalyzeParams(BaseModel):
    repo_path: str = Field(default="", description="Absolute path to target repository root.")
    coverage_file: str = Field(default="", description="Path to existing coverage report file (coverage.json, coverage.xml, lcov.info).")
    test_command: str = Field(default="pytest --cov --cov-report=term-missing", description="Test command to run for coverage generation.")
    include_exts: list[str] = Field(default=[".py", ".js", ".ts", ".go", ".rs"], description="Source file extensions to measure.")


class CoverageAnalyzerTool(BaseTool[CoverageAnalyzeParams]):
    name = "coverage_analyze"
    description = (
        "Test Coverage Gap Analyzer (Phase 1): Identifies untested functions, files, and branch targets. "
        "Surfaces uncovered sensitive sinks that require dedicated fuzzer/harness development."
    )
    params = CoverageAnalyzeParams
    mutating = False
    prompt_guidelines = ()

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

        # Try multiple candidate paths (defensive: handle .coverage binary, lcov, cobertura, json)
        candidates: list[Path] = []
        if params.coverage_file:
            candidates.append(Path(params.coverage_file))
        else:
            candidates.extend([
                repo / "coverage.json",
                repo / "coverage.out",
                repo / "coverage.xml",
                repo / "lcov.info",
                repo / ".coverage.json",
                repo / "htmlcov" / "index.html",
                repo / ".coverage",  # last: binary pickle is unparseable but try
            ])
        for cp in candidates:
            if cp.exists() and cp.is_file():
                # Skip binary pickle unless no alternative
                if cp.name == ".coverage" and any(c.exists() for c in candidates if c.name != ".coverage"):
                    continue
                try:
                    # Quick binary check
                    head = cp.read_bytes()[:4]
                    if head.startswith(b"\x00") or head.startswith(b"\x80"):  # pickle
                        continue
                except OSError:
                    continue
                return self._parse_existing_coverage(repo, cp, params.include_exts)

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
                # support both pytest-cov {files:{}} and coverage.py {files:[]}
                files = data.get("files", {})
                if isinstance(files, dict):
                    for file_path, info in files.items():
                        summary.append(f"{file_path}: {info.get('summary', {})}")
                        missing = info.get("missing_lines", info.get("missing_branches", []))
                        if missing:
                            gaps.append((file_path, "lines", len(missing)))
                elif isinstance(files, list):
                    for info in files:
                        fp = info.get("filename", "unknown")
                        missing = info.get("missing_lines", [])
                        if missing:
                            gaps.append((fp, "lines", len(missing)))
            elif cov_path.suffix == ".xml":
                # Cobertura XML
                text = cov_path.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'class\s+filename="([^"]+)"[^>]*line-rate="([0-9.]+)"', text):
                    rate = float(m.group(2))
                    if rate < 1.0:
                        gaps.append((m.group(1), "lines", int((1 - rate) * 100)))
            else:
                text = cov_path.read_text(encoding="utf-8", errors="ignore")
                # term-missing text
                for m in re.finditer(
                    r"(?P<path>\S+)\s+(?P<pct>\d+)%\s+(?P<miss>\d+)",
                    text,
                ):
                    gaps.append((m.group("path"), "lines", int(m.group("miss"))))
                # lcov / go cover
                if not gaps:
                    for m in re.finditer(r"SF:(.+)", text):
                        gaps.append((m.group(1).strip(), "lines", 1))
                    for m in re.finditer(r"(.+):\d+\.\d+,\d+\.\d+\s+1\s+0", text):
                        gaps.append((m.group(1).strip(), "lines", 1))
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
