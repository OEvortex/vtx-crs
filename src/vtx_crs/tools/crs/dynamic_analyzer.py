"""Dynamic analysis tool: strace, ltrace, timeout monitoring, crash detection."""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import time
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


class DynamicAnalyzeParams(BaseModel):
    command: str = Field(..., description="Shell command or script to execute under dynamic instrumentation.")
    repo_path: str = Field(default="", description="Working directory for execution. Defaults to the active case repo.")
    timeout_seconds: int = Field(default=30, description="Execution timeout in seconds.")
    strace: bool = Field(default=True, description="Enable strace syscall tracing.")
    ltrace: bool = Field(default=False, description="Enable ltrace library-call tracing.")
    env: dict[str, str] = Field(default_factory=dict, description="Extra environment variables for the execution environment.")


class DynamicAnalyzerTool(BaseTool[DynamicAnalyzeParams]):
    name = "dynamic_analyze"
    description = (
        "Executes a command under strace/ltrace monitoring to capture syscalls, crashes, and suspicious runtime behavior. "
        "Use on binaries or scripts after static analysis. Call with command set to the target invocation."
    )
    params = DynamicAnalyzeParams
    mutating = False
    prompt_guidelines = ()

    async def execute(
        self, params: DynamicAnalyzeParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid path",
                ui_details="",
            )

        started = time.monotonic()
        env = os.environ.copy()
        env.update({k: str(v) for k, v in params.env.items()})

        cmd = params.command
        import tempfile

        tmp_strace = tempfile.NamedTemporaryFile(prefix="vtx_strace_", suffix=".out", delete=False)
        strace_path = Path(tmp_strace.name)
        tmp_strace.close()
        strace_cmd = None
        use_strace = params.strace and shutil.which("strace")
        use_ltrace = params.ltrace and shutil.which("ltrace")
        if use_ltrace and not use_strace:
            # ltrace direct
            strace_cmd = ["ltrace", "-f", "-tt", "-o", str(strace_path), "sh", "-c", cmd]
        elif use_strace:
            strace_flags = ["-f", "-tt", "-T", "-o", str(strace_path)]
            strace_cmd = ["strace", *strace_flags, "sh", "-c", cmd]
        else:
            strace_cmd = ["sh", "-c", cmd]

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *strace_cmd,
                cwd=str(repo),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=params.timeout_seconds
            )
            output = (stdout_bytes or b"").decode("utf-8", errors="replace")
            exit_code = proc.returncode
            timed_out = False
        except TimeoutError:
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.kill()
            output = f"Process timed out after {params.timeout_seconds}s."
            exit_code = -1
            timed_out = True
        except Exception as e:
            output = f"Execution error: {e}"
            exit_code = -1
            timed_out = False
        duration = round(time.monotonic() - started, 1)

        sections = [
            "## Dynamic Analysis",
            f"- Command: {cmd}",
            f"- Exit code: {exit_code}",
            f"- Duration: {duration}s",
            f"- Timed out: {timed_out}",
        ]

        # Parse strace output if available
        if strace_path.exists() and params.strace:
            trace_text = strace_path.read_text(errors="replace")
            trace_summary = self._summarize_trace(trace_text)
            sections.append("")
            sections.append("### Syscall Summary")
            sections.append(trace_summary)

        # Detect crashes
        crash_signals = ["segfault", "sigsegv", "abort", "bus error", "core dumped"]
        crash_finding = None
        if any(sig in output.lower() for sig in crash_signals):
            sections.append("")
            sections.append("### CRASH DETECTED")
            sections.append(
                "Process crashed during execution. This is a potential vulnerability indicator."
            )
            crash_finding = VulnerabilityFinding(
                title="Runtime crash under dynamic analysis",
                description=f"Command '{cmd}' crashed with exit code {exit_code}.",
                severity=Severity.CRITICAL,
                cwe_id="CWE-121",
                file_path=str(repo),
                evidence=[output[-2000:]],
                source="dynamic",
            )
            case = _case_manager.active_case
            case.add_finding(crash_finding)
            _case_manager.save_active()

        output_lines = output.strip().splitlines()
        tail = output_lines[-25:] if len(output_lines) > 25 else output_lines
        sections.append("")
        sections.append("### Output (tail)")
        sections.extend(f"  {line}" for line in tail)

        text = "\n".join(sections)
        return ToolResult(
            success=exit_code == 0,
            result=text,
            ui_summary=f"Dynamic analysis: exit={exit_code} duration={duration}s",
            ui_details=text,
        )

    def _summarize_trace(self, trace_text: str) -> str:
        lines = trace_text.splitlines()
        syscalls: dict[str, int] = {}
        errors = 0
        # Handle strace -tt prefix: "12345 12:34:56.123456 syscall(args) = ret" and ltrace similarly
        for line in lines:
            # strip pid + timestamp prefix
            stripped = re.sub(r"^\s*\d+\s+\d+:\d+:\d+\.\d+\s+", "", line)
            stripped = re.sub(r"^\s*\d+\s+", "", stripped)
            m = re.match(r"(\w+)\s*\(.*\)\s*=\s*([-\d]+|\?|0x[0-9a-fA-F]+)", stripped)
            if m:
                syscall = m.group(1)
                syscalls[syscall] = syscalls.get(syscall, 0) + 1
                ret = m.group(2)
                if ret == "-1" or ret == "?":
                    errors += 1
        top = sorted(syscalls.items(), key=lambda x: -x[1])[:15]
        parts = [f"- {name}: {count} call(s)" for name, count in top]
        parts.append(f"- Errors: {errors}")
        # Highlight dangerous syscalls (offensive+defensive)
        dangerous = {"execve", "mprotect", "mmap", "socket", "connect", "ptrace", "chmod", "openat"}
        hits = [k for k in syscalls if k in dangerous]
        if hits:
            parts.append(f"- Dangerous: {', '.join(sorted(hits))}")
        return "\n".join(parts) if parts else "(no syscalls parsed)"


__all__ = ["DynamicAnalyzerTool"]
