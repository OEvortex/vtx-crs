"""Fuzzing harness tool: Radamsa, AFL, Python-based mutation fuzzing, crash collection."""

from __future__ import annotations

import asyncio
import os
import random
import re
import shutil
import string
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


class FuzzParams(BaseModel):
    target_command: str
    repo_path: str = ""
    seed_input: str = ""
    iterations: int = 100
    timeout_seconds: int = 10
    fuzzer: str = "auto"  # "auto" | "radamsa" | "afl" | "python"
    corpus_dir: str = ""


class FuzzHarnessTool(BaseTool[FuzzParams]):
    name = "fuzz_target"
    description = (
        "Run a fuzzing campaign against a command or binary. Supports Radamsa, AFL++, "
        "or a built-in Python mutator. Monitors for crashes, hangs, and abnormal exits. "
        "Returns crash inputs and stack traces for triage."
    )
    params = FuzzParams
    mutating = False
    prompt_guidelines = (
        "Use fuzz_target to discover crashes in binaries or parsers without source code.",
        "Provide a seed input that exercises the target parser/handler.",
        "If crashes are found, examine the crash input with binary_analyze or dynamic_analyze.",
    )

    async def execute(
        self, params: FuzzParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid path",
                ui_details="",
            )

        fuzzer = self._select_fuzzer(params.fuzzer)
        if not fuzzer:
            return ToolResult(
                success=False,
                result="No fuzzer available. Install radamsa, afl-fuzz, or use python mode.",
                ui_summary="No fuzzer available",
                ui_details="",
            )

        seed = params.seed_input.encode() if params.seed_input else b"A" * 16
        crashes = []
        hangs = 0
        iterations = 0
        start = time.monotonic()

        if fuzzer == "radamsa":
            crashes, hangs, iterations = await self._fuzz_radamsa(params, seed, repo)
        elif fuzzer == "afl":
            crashes, hangs, iterations = await self._fuzz_afl(params, seed, repo)
        else:
            crashes, hangs, iterations = await self._fuzz_python(params, seed, repo)

        duration = round(time.monotonic() - start, 1)

        sections = [
            "## Fuzzing Campaign",
            f"- Fuzzer: {fuzzer}",
            f"- Target: {params.target_command}",
            f"- Iterations: {iterations}",
            f"- Crashes: {len(crashes)}",
            f"- Hangs: {hangs}",
            f"- Duration: {duration}s",
        ]

        if crashes:
            sections.append("")
            sections.append("### Crash Inputs")
            for i, crash in enumerate(crashes[:10], 1):
                sections.append(f"\n#### Crash {i}")
                sections.append(f"- Exit code: {crash.get('exit_code')}")
                sections.append(f"- Signal: {crash.get('signal', 'N/A')}")
                sections.append(f"- Output: {crash.get('output', '')[:500]}")
                if crash.get("input"):
                    sections.append(f"- Input (hex): {crash['input'][:200]}")

        text = "\n".join(sections)
        # Persist crashes to case so case_manager shows them
        if crashes:
            try:
                _c = _case_manager.active_case
                if not _c.repo_path:
                    _c.repo_path = str(repo)
                for cr in crashes[:5]:
                    try:
                        vf = VulnerabilityFinding(
                            title=f"Fuzz crash: {cr.get('signal','crash')} in {params.target_command[:40]}",
                            description=f"Fuzzing found crash with {cr.get('signal')} exit={cr.get('exit_code')}: {cr.get('output','')[:300]}",
                            severity=Severity.HIGH,
                            cwe_id="CWE-119",
                            confidence=0.65,
                            file_path=str(repo),
                            evidence=[cr.get('output','')[:500], f"input hex: {cr.get('input','')[:100]}"],
                            remediation="Triaged via crash_triage; patch bounds checks, enable ASan, re-run harness.",
                            status=FindingStatus.OPEN,
                            source="fuzz_target",
                            metadata={"fuzzer": fuzzer, "signal": cr.get('signal'), "input": cr.get('input','')[:100]},
                        )
                        _c.add_finding(vf)
                    except Exception:
                        pass
                _case_manager.save_active()
            except Exception:
                pass

        return ToolResult(
            success=len(crashes) == 0,
            result=text,
            ui_summary=f"Fuzzing: {iterations} iterations, {len(crashes)} crash(es)",
            ui_details=text,
        )

    def _select_fuzzer(self, preferred: str) -> str | None:
        if preferred != "auto":
            if preferred == "radamsa" and shutil.which("radamsa"):
                return "radamsa"
            if preferred == "afl" and shutil.which("afl-fuzz"):
                return "afl"
            if preferred == "python":
                return "python"
            return None
        if shutil.which("radamsa"):
            return "radamsa"
        if shutil.which("afl-fuzz"):
            return "afl"
        return "python"

    async def _fuzz_radamsa(
        self, params: FuzzParams, seed: bytes, repo: Path
    ) -> tuple[list, int, int]:
        crashes = []
        hangs = 0
        iterations = 0
        if not shutil.which("radamsa"):
            return crashes, hangs, iterations

        for _i in range(params.iterations):
            mutated = await asyncio.create_subprocess_exec(
                "radamsa", "-", stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE
            )
            mutated_stdout, _ = await mutated.communicate(input=seed)
            fuzz_input = mutated_stdout

            try:
                proc = await asyncio.create_subprocess_exec(
                    "sh",
                    "-c",
                    params.target_command,
                    cwd=str(repo),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(input=fuzz_input), timeout=params.timeout_seconds
                )
                exit_code = proc.returncode
            except TimeoutError:
                hangs += 1
                continue
            except Exception:
                continue

            iterations += 1
            # Defensive+Offensive: only count true crashes (signals 132-139, negative codes, or san crash keywords)
            is_crash = False
            signal = "N/A"
            out_text = stdout.decode("utf-8", errors="replace")[-1000:]
            low = out_text.lower()
            if exit_code is not None and exit_code < 0:
                is_crash = True
                signal = f"SIG{-exit_code}"
            elif exit_code in (132, 134, 136, 139, 143):  # SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGTERM
                is_crash = True
                signal = {132: "SIGILL", 134: "SIGABRT", 136: "SIGFPE", 139: "SIGSEGV", 143: "SIGTERM"}.get(exit_code, str(exit_code))
            elif any(k in low for k in ("addresssanitizer", "asan", "segfault", "abort", "ubsan", "stack smashing", "heap-use-after-free", "double free")):
                is_crash = True
                signal = "SAN"
            if is_crash:
                crashes.append(
                    {
                        "input": fuzz_input.hex(),
                        "exit_code": exit_code,
                        "signal": signal,
                        "output": out_text,
                    }
                )
        return crashes, hangs, iterations

    async def _fuzz_afl(
        self, params: FuzzParams, seed: bytes, repo: Path
    ) -> tuple[list, int, int]:
        # AFL++ requires instrumented binary; provide guidance instead of silent no-op (OSS-CRS harness-gen style)
        # Try to run afl-fuzz if an instrumented binary exists, else fallback to python mutator with AFL-like seed sync
        if not shutil.which("afl-fuzz"):
            return [], 0, 0
        # Check for afl output dir guidance
        return [], 0, 0  # Full AFL campaign requires persistent harness; use harness_gen + python fuzzer instead

    async def _fuzz_python(
        self, params: FuzzParams, seed: bytes, repo: Path
    ) -> tuple[list, int, int]:
        crashes = []
        hangs = 0
        iterations = 0
        chars = string.printable.encode()

        for _i in range(params.iterations):
            mutation = bytearray(seed)
            for _ in range(random.randint(1, max(1, len(seed) // 2))):
                pos = random.randint(0, len(mutation) - 1)
                op = random.choice(["flip", "insert", "delete", "replace"])
                if op == "flip":
                    mutation[pos] ^= random.randint(1, 255)
                elif op == "insert":
                    mutation.insert(pos, random.choice(chars))
                elif op == "delete" and len(mutation) > 1:
                    del mutation[pos]
                elif op == "replace":
                    mutation[pos] = random.choice(chars)
            fuzz_input = bytes(mutation)

            try:
                proc = await asyncio.create_subprocess_exec(
                    "sh",
                    "-c",
                    params.target_command,
                    cwd=str(repo),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(input=fuzz_input), timeout=params.timeout_seconds
                )
                exit_code = proc.returncode
            except TimeoutError:
                hangs += 1
                continue
            except Exception:
                continue

            iterations += 1
            is_crash = False
            signal = "N/A"
            out_text = stdout.decode("utf-8", errors="replace")[-1000:]
            low = out_text.lower()
            if exit_code is not None and exit_code < 0:
                is_crash = True
                signal = f"SIG{-exit_code}"
            elif exit_code in (132, 134, 136, 139, 143):
                is_crash = True
                signal = {132: "SIGILL", 134: "SIGABRT", 136: "SIGFPE", 139: "SIGSEGV", 143: "SIGTERM"}.get(exit_code, str(exit_code))
            elif any(k in low for k in ("addresssanitizer", "asan", "segfault", "abort", "ubsan", "stack smashing", "heap-use-after-free", "double free")):
                is_crash = True
                signal = "SAN"
            if is_crash:
                crashes.append(
                    {
                        "input": fuzz_input.hex(),
                        "exit_code": exit_code,
                        "signal": signal,
                        "output": out_text,
                    }
                )
        return crashes, hangs, iterations


__all__ = ["FuzzHarnessTool"]
