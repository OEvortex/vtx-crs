"""Crash triage: classify and localize crash artifacts.

Accepts crash logs, sanitizer output, core dump metadata, or similar text
artifacts. Surfaces crash type, likely faulting file/function, and remediation
guidance.
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

from ._common import resolve_repo_path

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class CrashTriageParams(BaseModel):
    crash_file: str = Field(default="", description="Path to crash log or core dump report file.")
    crash_text: str = Field(default="", description="Verbatim crash log text (ASan, UBSan, GDB stack trace, segfault output).")
    repo_path: str = Field(default="", description="Base repository path for source line localization.")


class CrashTriagerTool(BaseTool[CrashTriageParams]):
    name = "crash_triage"
    description = (
        "Crash Artifact Classifier & Root-Cause Localizer (Phase 2): Parses sanitizer logs (ASan, UBSan, MSan), "
        "segfault backtraces, and core dumps. Extracts faulting function, line number, memory fault type, and crash signals."
    )
    params = CrashTriageParams
    mutating = False
    prompt_guidelines = ()

    async def execute(
        self, params: CrashTriageParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)

        text = params.crash_text.strip()
        crash_path = Path(params.crash_file) if params.crash_file else None
        if not text and crash_path and crash_path.exists():
            try:
                text = crash_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass

        if not text:
            return ToolResult(
                success=False,
                result="Provide crash_text or crash_file.",
                ui_summary="Missing crash input",
                ui_details="",
            )

        crash_type = self._classify(text)
        location = self._localize(text)
        signals = self._parse_signals(text)

        lines_out = [
            f"Crash type: {crash_type}",
            "",
            f"Faulting location: {location or 'unknown'}",
            "",
            "Signals detected:",
        ]
        if signals:
            for s in signals:
                lines_out.append(f"  - {s}")
        else:
            lines_out.append("  (none parsed)")

        lines_out += [
            "",
            "Remediation guidance:",
            "  1. Reproduce with the provided input using build_runner / test_runner.",
            "  2. Verify the crash with ASan/UBSan if available.",
            "  3. Inspect the faulting function for missing validation or bounds checks.",
            "  4. Patch with the minimal safe fix and re-run the failing test.",
        ]

        result_text = "\n".join(lines_out)
        # Persist crash triage as finding
        try:
            _c = _case_manager.active_case
            # auto-attach repo if needed
            if not _c.repo_path and 'repo' in locals() and repo.exists():
                _c.repo_path = str(repo)
            vf = VulnerabilityFinding(
                title=f"Crash: {crash_type}",
                description=f"Crash triaged as {crash_type} at {location or 'unknown'} with signals {signals}",
                severity=Severity.HIGH if "overflow" in crash_type.lower() or "sanitizer" in crash_type.lower() else Severity.MEDIUM,
                cwe_id="CWE-119",
                confidence=0.6,
                file_path=location or str(repo) if 'repo' in locals() else "unknown",
                evidence=[text[:1000]],
                remediation="Reproduce with harness, enable ASan, patch bounds checks, re-run exploit_feasibility.",
                status=FindingStatus.OPEN,
                source="crash_triage",
                metadata={"crash_type": crash_type, "location": location or "", "signals": signals},
            )
            _c.add_finding(vf)
            _case_manager.save_active()
        except Exception:
            pass

        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"Crash triage: {crash_type}",
            ui_details=result_text,
        )

    @staticmethod
    def _classify(text: str) -> str:
        low = text.lower()
        if "addresssanitizer" in low or "asan" in low:
            return "AddressSanitizer (heap/stack overflow, use-after-free)"
        if "undefined behavior sanitizer" in low or "ubsan" in low:
            return "UBSan (undefined behavior)"
        if "segmentation fault" in low or "segfault" in low or "sigsegv" in low:
            return "Segmentation fault"
        if "abort" in low or "aborted" in low:
            return "Aborted (assertion failure or fatal signal)"
        if "heap overflow" in low:
            return "Heap overflow"
        if "stack overflow" in low:
            return "Stack overflow"
        if "use-after-free" in low:
            return "Use-after-free"
        if "double free" in low:
            return "Double free"
        return "Unknown crash"

    @staticmethod
    def _localize(text: str) -> str | None:
        m = re.search(r"(?:in\s+)([A-Za-z0-9_:./]+(?:\.[A-Za-z0-9_]+)+)\s*\(", text)
        if m:
            return m.group(1)
        m = re.search(r"(?:at\s+)([A-Za-z0-9_:./]+(?:\.[A-Za-z0-9_]+)+)\s*[:]", text)
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _parse_signals(text: str) -> list[str]:
        signals: list[str] = []
        for pat, label in [
            (r"READ of size \d+", "Invalid read"),
            (r"WRITE of size \d+", "Invalid write"),
            (r"heap-use-after-free", "Heap use-after-free"),
            (r"stack-use-after-return", "Stack use-after-return"),
            (r"double-free", "Double free detected"),
            (r"alloc-dealloc-mismatch", "Allocator mismatch"),
            (r"memcpy-param-overlap", "Overlapping memcpy"),
            (r"negative-size-param", "Negative size param"),
            (r"integer-overflow", "Integer overflow"),
            (r"null-pointer-dereference", "Null pointer dereference"),
            (r"out-of-memory", "Out of memory"),
        ]:
            if re.search(pat, text, re.IGNORECASE):
                signals.append(label)
        return signals
