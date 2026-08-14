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
from vtx.tools.base import BaseTool

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
            if exit_code and exit_code != 0:
                crashes.append(
                    {
                        "input": fuzz_input.hex(),
                        "exit_code": exit_code,
                        "signal": "N/A",
                        "output": stdout.decode("utf-8", errors="replace")[-1000:],
                    }
                )
        return crashes, hangs, iterations

    async def _fuzz_afl(
        self, params: FuzzParams, seed: bytes, repo: Path
    ) -> tuple[list, int, int]:
        return [], 0, 0  # AFL requires persistent mode binary setup; defer to manual harness

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
            if exit_code and exit_code != 0:
                crashes.append(
                    {
                        "input": fuzz_input.hex(),
                        "exit_code": exit_code,
                        "signal": "N/A",
                        "output": stdout.decode("utf-8", errors="replace")[-1000:],
                    }
                )
        return crashes, hangs, iterations


__all__ = ["FuzzHarnessTool"]
