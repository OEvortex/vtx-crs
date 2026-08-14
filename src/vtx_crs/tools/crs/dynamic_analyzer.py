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
from vtx.tools.base import BaseTool

from vtx_crs.core import FindingStatus, Severity, VulnerabilityFinding, get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


class DynamicAnalyzeParams(BaseModel):
    command: str
    repo_path: str = ""
    timeout_seconds: int = 30
    strace: bool = True
    ltrace: bool = False
    env: dict[str, str] = {}


class DynamicAnalyzerTool(BaseTool[DynamicAnalyzeParams]):
    name = "dynamic_analyze"
    description = (
        "Run a command under dynamic analysis instrumentation: strace (syscalls), "
        "ltrace (library calls), and crash/timeout monitoring. Use this to observe "
        "runtime behavior, detect crashes, and identify interesting syscalls "
        "(open, execve, socket, connect, etc.)."
    )
    params = DynamicAnalyzeParams
    mutating = False
    prompt_guidelines = (
        "Use dynamic_analyze to observe runtime behavior of binaries or scripts.",
        "Look for crashes (segfault, abort), dangerous syscalls (execve, mprotect), "
        "and file/network access patterns.",
        "Combine with binary_analyze to correlate static symbols with runtime calls.",
    )

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
        strace_path = Path("/tmp/strace.out")
        strace_cmd = None
        if params.strace and shutil.which("strace"):
            strace_flags = ["-f", "-tt", "-T", "-o", str(strace_path)]
            if params.ltrace:
                strace_flags.extend(["-l"])
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
        syscalls = {}
        errors = 0
        for line in lines:
            m = re.match(r"\w+\(([^)]+)\)\s*=\s*([-\d]+|\?)", line)
            if m:
                syscall = line.split("(")[0].strip()
                syscalls[syscall] = syscalls.get(syscall, 0) + 1
                ret = m.group(2)
                if ret == "-1" or ret == "?":
                    errors += 1
        top = sorted(syscalls.items(), key=lambda x: -x[1])[:15]
        parts = [f"- {name}: {count} call(s)" for name, count in top]
        parts.append(f"- Errors: {errors}")
        return "\n".join(parts) if parts else "(no syscalls parsed)"


__all__ = ["DynamicAnalyzerTool"]
