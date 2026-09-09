"""Attack surface & threat-model synthesis (defensive).

Combines repo_analyze + service_analyze signals into a
structured threat model, similar to RAPTOR threat-model.json / OSS-CRS target analysis.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from pydantic import BaseModel, Field
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import get_case_manager
from ._common import iter_source_files, resolve_repo_path, MAX_FILE_BYTES

_case_manager = get_case_manager()


class AttackSurfaceParams(BaseModel):
    repo_path: str = Field(default="", description="Project root path. Defaults to the active case repo.")
    include_trust_boundaries: bool = Field(default=True, description="Include trust boundary and auth-gap mappings in the output.")


class AttackSurfaceTool(BaseTool[AttackSurfaceParams]):
    name = "attack_surface"
    description = (
        "Maps repository attack surfaces and trust boundaries. Use after repo_analyze to prioritize "
        "unauthenticated entry points, network binds, and sensitive sinks. Call with repo_path set to the project root."
    )
    params = AttackSurfaceParams
    mutating = False
    prompt_guidelines = ()

    async def execute(self, params: AttackSurfaceParams, cancel_event: asyncio.Event | None = None) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(success=False, result=f"Repo not found: {repo}", ui_summary="Invalid repo", ui_details="")

        # Gather signals
        entry_points: list[str] = []
        handlers: list[str] = []
        auth_gaps: list[str] = []
        trust_boundaries: list[str] = []
        crown_jewels: list[str] = []

        for path in iter_source_files(repo, {".py", ".js", ".ts", ".go", ".java", ".rs", ".c", ".cpp"}):
            if cancel_event and cancel_event.is_set():
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(repo))
            low = text.lower()
            # Entry points
            if re.search(r"(?:@app\.route|app\.(get|post|put|delete)\(|router\.(get|post)|HandleFunc|http\.Handle)", text):
                entry_points.append(rel)
            if re.search(r"(?:bind\(|listen\(|0\.0\.0\.0|INADDR_ANY|server\.listen)", text):
                handlers.append(f"{rel}: binds all interfaces")
            if re.search(r"(?:auth|login|session|jwt|token)", low) is None and re.search(r"(?:app\.route|api/)", low):
                auth_gaps.append(f"{rel}: route without visible auth")
            # Secrets / crown jewels
            if re.search(r"(?:password|secret|api[_-]?key|private[_-]?key|aws_)", low):
                crown_jewels.append(rel)
            if re.search(r"(?:SELECT|INSERT|UPDATE|DELETE|FROM\s+\w+)", text, re.I):
                crown_jewels.append(f"{rel}: DB query")

        # Deduplicate
        entry_points = sorted(set(entry_points))[:20]
        handlers = sorted(set(handlers))[:15]
        auth_gaps = sorted(set(auth_gaps))[:15]
        crown_jewels = sorted(set(crown_jewels))[:15]

        if params.include_trust_boundaries:
            trust_boundaries = [
                "Internet -> HTTP handlers (unauthenticated by default)",
                "App -> DB (SQL taint boundary)",
                "App -> OS (command injection boundary)",
                "App -> Filesystem (path traversal boundary)",
                "App -> Deserializer (pickle/yaml boundary)",
            ]

        lines = [
            "## Attack Surface & Threat Model (Defensive)",
            f"- Repo: {repo}",
            f"- Entry points (routes/handlers): {len(entry_points)}",
            f"- Network handlers: {len(handlers)}",
            f"- Auth gaps (candidate): {len(auth_gaps)}",
            f"- Crown jewels (DB/secrets): {len(crown_jewels)}",
            "",
            "### Entry Points",
        ]
        for e in entry_points or ["(none detected — check repo_analyze)"]:
            lines.append(f"- {e}")
        lines.append("")
        lines.append("### Network Attack Surface")
        for h in handlers or ["(none detected)"]:
            lines.append(f"- {h}")
        if auth_gaps:
            lines.append("")
            lines.append("### Auth Gaps (verify manually)")
            for a in auth_gaps:
                lines.append(f"- {a}")
        if crown_jewels:
            lines.append("")
            lines.append("### Crown Jewels / Sensitive Sinks")
            for c in crown_jewels:
                lines.append(f"- {c}")
        if trust_boundaries:
            lines.append("")
            lines.append("### Trust Boundaries")
            for t in trust_boundaries:
                lines.append(f"- {t}")
        lines.extend([
            "",
            "### Prioritization (defensive)",
            "- Patch unauthenticated entry -> sink flows first (see taint flows in unified_scan).",
            "2. Harden network binds (mitigation_inject).",
            "3. Validate fixes with patch_validate.",
            "",
            "### Offensive use",
            "- Focus fuzz_target/dynamic_analyze on entry points above.",
            "- Craft PoCs via offensive_chain for each sink near an entry point.",
        ])
        text = "\n".join(lines)
        return ToolResult(success=True, result=text, ui_summary=f"Attack surface: {len(entry_points)} entries, {len(auth_gaps)} auth gaps", ui_details=text)
