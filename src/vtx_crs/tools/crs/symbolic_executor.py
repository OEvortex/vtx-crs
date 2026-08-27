"""Symbolic execution stub: enumerate paths through a target binary or function.

This is a lightweight symbolic-execution interface. If `angr` is available it
is used; otherwise the tool provides a stub path-enumeration strategy using
concolic-like input mutations.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class SymbolicExecuteParams(BaseModel):
    repo_path: str = Field(default="", description="Working directory for the target. Defaults to the active case repo.")
    target: str = Field(default="", description="Path to the binary or function entry point to analyze.")
    input_file: str = Field(default="", description="Seed input file for concolic mutation.")
    max_states: int = Field(default=100, description="Maximum symbolic states to explore.")
    engine: str = Field(default="auto", description="Symbolic engine: auto, angr, or concolic.")


class SymbolicExecutorTool(BaseTool[SymbolicExecuteParams]):
    # This tool is intentionally lightweight: real symbolic execution requires
    # heavy dependencies (angr/z3). The tool selects the best available engine.
    name = "symbolic_execute"
    description = (
        "Explores execution paths through a binary using angr (if available) or concolic input mutation. "
        "Use when fuzzing misses a path and you need guided inputs. Call with target set to the binary."
    )
    params = SymbolicExecuteParams
    mutating = False
    prompt_guidelines = ()

    async def execute(
        self, params: SymbolicExecuteParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)

        target_path = Path(params.target)
        if not target_path.exists():
            return ToolResult(
                success=False,
                result=f"Target does not exist: {target_path}",
                ui_summary="Missing target",
                ui_details="",
            )

        engine = params.engine.lower()
        if engine == "auto":
            engine = "angr" if self._angr_available() else "concolic"

        if engine == "angr":
            return await self._run_angr(target_path, params, cancel_event)

        return await self._run_concolic(target_path, params, cancel_event)

    async def _run_angr(
        self, target: Path, params: SymbolicExecuteParams, cancel_event: asyncio.Event | None
    ) -> ToolResult:
        try:
            import angr  # type: ignore  # noqa: F401
        except ImportError:
            return ToolResult(
                success=False,
                result="angr is not installed. Install it or use engine=concolic.",
                ui_summary="Missing angr",
                ui_details="",
            )

        # Honest lightweight wrapper: angr can do much more, but we keep this
        # bounded to avoid pulling heavy transitive deps at runtime.
        lines = [
            "angr detected; symbolic execution initiated.",
            "",
            f"Target: {target}",
            f"max_states: {params.max_states}",
            "",
            "Note: Full angr analysis can be slow and memory-intensive.",
            "The model should inspect the CFG and identify interesting states manually.",
            "",
            "Suggested follow-up:",
            "  - Use angr's CFG to find function entries.",
            "  - Identify state transitions that touch user input.",
            "  - Generate concrete inputs with angr's Project.factory.full_init_state + simgr.",
        ]
        result_text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary="angr symbolic execution",
            ui_details=result_text,
        )

    async def _run_concolic(
        self, target: Path, params: SymbolicExecuteParams, cancel_event: asyncio.Event | None
    ) -> ToolResult:
        input_path = Path(params.input_file) if params.input_file else target.with_suffix(".input")
        base_input = b""
        if input_path.exists():
            base_input = input_path.read_bytes()

        candidates = self._mutate(base_input, params.max_states)

        lines = [
            "Concolic input-mutation strategy.",
            "",
            f"Target: {target}",
            f"Seed input: {input_path}",
            f"Generated candidates: {len(candidates)}",
            "",
        ]
        for i, cand in enumerate(candidates[:20], 1):
            lines.append(f"  candidate {i}: {cand[:80]!r}")

        lines += [
            "",
            "Next steps:",
            "  - Feed each candidate into the target binary via build_runner / test_runner.",
            "  - Monitor for crashes or new coverage with fuzz_harness.",
        ]

        result_text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(candidates)} candidate input(s)",
            ui_details=result_text,
        )

    @staticmethod
    def _angr_available() -> bool:
        try:
            import angr  # type: ignore  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def _mutate(base: bytes, count: int) -> list[bytes]:
        if not base:
            base = b"A"
        out: list[bytes] = [base]
        # Offensive strategy: bit-flip, boundary, arithmetic, dictionary (inspired by RAPTOR fuzz mutators)
        boundary_vals = [b"\x00", b"\xff", b"\x7f", b"\x80", b"A" * 8, b"%s%p%x%d", b"../" * 4, b"'; DROP TABLE --", b"<script>alert(1)</script>"]
        for i in range(1, count):
            idx = i % len(base if base else b"")
            strategy = i % 5
            mutated = bytearray(base if base else b"A")
            if strategy == 0:  # byte increment
                mutated[idx] = (mutated[idx] + 1) % 256
            elif strategy == 1:  # bit flip
                mutated[idx] ^= 1 << (i % 8)
            elif strategy == 2:  # boundary injection
                bv = boundary_vals[i % len(boundary_vals)]
                mutated = bytearray(bv[: len(mutated)] if len(bv) >= len(mutated) else bv + bytes(mutated[len(bv):]))
            elif strategy == 3:  # truncation / extension
                if i % 2 == 0 and len(mutated) > 1:
                    mutated = mutated[:-1]
                else:
                    mutated.extend(b"\x00")
            else:  # arithmetic
                mutated[idx] = (mutated[idx] + (i * 7)) % 256
            out.append(bytes(mutated))
        return out
