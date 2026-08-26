"""Generate fuzz/PoC harnesses for target functions or binaries.

Creates minimal harness code that calls a target function with structured
inputs. The model is expected to compile and run the harness under a fuzzer.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.coding_agent.tools import BaseTool

from vtx_crs.core import get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


class HarnessGenParams(BaseModel):
    repo_path: str = ""
    target_file: str = ""
    target_function: str = ""
    language: str = "python"
    output_path: str = ""
    poc_type: str = "python"  # python | c | rust


class HarnessGeneratorTool(BaseTool[HarnessGenParams]):
    name = "harness_gen"
    description = (
        "Generate a minimal fuzz/PoC harness for a target function or binary entry "
        "point. The harness is written to disk and can be built and run under the "
        "project's fuzzer or test runner."
    )
    params = HarnessGenParams
    mutating = True
    prompt_guidelines = (
        "Run harness_gen after vuln_scan or crash_triage to turn a sink into a runnable target.",
        "Use the harness with build_runner and test_runner to reproduce the issue.",
        "Iterate: update the harness based on crash output from fuzz_harness.",
    )

    async def execute(
        self, params: HarnessGenParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)

        target = params.target_function or Path(params.target_file).stem
        poc_type = params.poc_type.lower()
        output_path = Path(params.output_path) if params.output_path else repo / "harness" / f"harness_{target}.{poc_type}"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        content = self._render(target, params.target_file, poc_type)

        try:
            output_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            return ToolResult(
                success=False,
                result=f"Failed to write harness: {exc}",
                ui_summary="Harness write failed",
                ui_details="",
            )

        result_text = (
            f"Harness written to: {output_path}\n\n"
            "Next steps:\n"
            f"  1. Inspect the harness.\n"
            f"  2. Build it: build_runner(build_command='python {output_path.name}' or equivalent).\n"
            f"  3. Fuzz: fuzz_harness with the harness as the seed corpus."
        )
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"Harness generated: {output_path.name}",
            ui_details=result_text,
        )

    @staticmethod
    def _render(target: str, target_file: str, poc_type: str) -> str:
        if poc_type == "python":
            return (
                f'"""Minimal harness for {target} from {target_file}."""\n\n'
                f"import argparse\nimport sys\n\n"
                f"def main() -> int:\n"
                f"    p = argparse.ArgumentParser()\n"
                f"    p.add_argument('input', nargs='?', default='')\n"
                f"    args = p.parse_args()\n\n"
                f"    # TODO: import {target} and call it with args.input.\n"
                f"    # Replace this stub with the real call after inspecting the source.\n"
                f"    print(f'Harness stub for {target}: {{args.input!r}}')\n"
                f"    return 0\n\n\n"
                f"if __name__ == '__main__':\n"
                f"    sys.exit(main())\n"
            )
        if poc_type == "c":
            return (
                f'/* Minimal harness for {target} from {target_file}. */\n\n'
                f"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n"
                f"int main(int argc, char **argv) {{\n"
                f"    const char *input = argc > 1 ? argv[1] : \"\";\n"
                f"    /* TODO: call {target}(input); */\n"
                f"    printf(\"Harness stub for {target}: %s\\n\", input);\n"
                f"    return 0;\n}}\n"
            )
        # rust / default
        return (
            f'// Minimal harness for {target} from {target_file}.\n\n'
            f"fn main() {{\n"
            f"    let input = std::env::args().nth(1).unwrap_or_default();\n"
            f"    // TODO: call {target}(&input);\n"
            f"    println!(\"Harness stub for {target}: {{}}\", input);\n}}\n"
        )
