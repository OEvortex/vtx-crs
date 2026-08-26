"""Generate a proof-of-concept (PoC) from a crash input or taint trace.

Produces a minimal program or script that reproduces the unsafe behavior.
This is intentionally conservative: the PoC demonstrates the bug without
weaponizing it beyond the required demonstration.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.coding_agent.tools import BaseTool

from vtx_crs.core import get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


class PovGenerateParams(BaseModel):
    repo_path: str = ""
    target_file: str = ""
    crash_input: str = ""
    crash_input_file: str = ""
    output_dir: str = ""
    poc_type: str = "python"


class PovGeneratorTool(BaseTool[PovGenerateParams]):
    name = "pov_generate"
    description = (
        "Generate a proof-of-concept (PoC) for a crash or taint flow. "
        "Writes a minimal reproducer to disk that demonstrates the bug with "
        "the provided crash input."
    )
    params = PovGenerateParams
    mutating = True
    prompt_guidelines = (
        "Run pov_generate after crash_triage or taint_analyze.",
        "Keep the PoC minimal and non-destructive; avoid network/system side effects.",
        "Use patch_validate to ensure the PoC still triggers after patching (expect failure).",
    )

    async def execute(
        self, params: PovGenerateParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)

        raw = params.crash_input.strip()
        if not raw and params.crash_input_file:
            p = Path(params.crash_input_file)
            if p.exists():
                try:
                    raw = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    pass
        if not raw:
            return ToolResult(
                success=False,
                result="Provide crash_input or crash_input_file.",
                ui_summary="Missing input",
                ui_details="",
            )

        output_dir = Path(params.output_dir) if params.output_dir else repo / "pocs"
        output_dir.mkdir(parents=True, exist_ok=True)

        poc_type = params.poc_type.lower()
        target = Path(params.target_file).stem if params.target_file else "poc"
        out_file = output_dir / f"poc_{target}.{poc_type}"

        content = self._render(target, params.target_file, poc_type, raw)
        try:
            out_file.write_text(content, encoding="utf-8")
        except OSError as exc:
            return ToolResult(
                success=False,
                result=f"Failed to write PoC: {exc}",
                ui_summary="PoC write failed",
                ui_details="",
            )

        result_text = (
            f"PoC written to: {out_file}\n\n"
            "Next steps:\n"
            f"  1. Build the PoC: build_runner.\n"
            f"  2. Run the PoC against the unfixed target.\n"
            f"  3. Re-run after patch_validate to confirm it no longer triggers."
        )
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"PoC generated: {out_file.name}",
            ui_details=result_text,
        )

    @staticmethod
    def _render(target: str, target_file: str, poc_type: str, raw: str) -> str:
        safe_input = raw.replace("\\", "\\\\").replace('"', '\\"')
        if poc_type == "python":
            return (
                f'"""Minimal PoC for {target} from {target_file}."""\n\n'
                f"import subprocess\nimport sys\nfrom pathlib import Path\n\n"
                f"INPUT = r\"{safe_input}\"\n\n\n"
                f"def main() -> int:\n"
                f"    target = Path(__file__).with_name(Path('{target_file}').name)\n"
                f"    if not target.exists():\n"
                f"        print(f'Target not found: {{target}}')\n"
                f"        return 2\n\n"
                f"    print('Running PoC against:' , target)\n"
                f"    p = subprocess.run([sys.executable, str(target)], input=INPUT, capture_output=True)\n"
                f"    print(p.stdout.decode('utf-8', 'replace'))\n"
                f"    if p.stderr:\n"
                f"        print(p.stderr.decode('utf-8', 'replace'), file=sys.stderr)\n"
                f"    print(f'Exit code: {{p.returncode}}')\n"
                f"    return p.returncode\n\n\n"
                f"if __name__ == '__main__':\n"
                f"    sys.exit(main())\n"
            )
        if poc_type == "c":
            hex_input = raw.encode("utf-8").hex()
            return (
                f'/* Minimal PoC for {target} from {target_file}. */\n\n'
                f"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n"
                f"static const unsigned char INPUT[] = \"{hex_input}\";\n\n"
                f"int main(int argc, char **argv) {{\n"
                f"    /* TODO: compile {target_file} and link against it. */\n"
                f"    printf(\"PoC stub for {target}. Raw input hex len=%zu\\n\", sizeof(INPUT)-1);\n"
                f"    return 0;\n}}\n"
            )
        # rust / default
        safe_rust = raw.replace("\\", "\\\\").replace('"', '\\"')
        return (
            f'// Minimal PoC for {target} from {target_file}.\n\n'
            f"fn main() {{\n"
            f"    let input = r#\"{safe_rust}\"#;\n"
            f"    println!(r\"PoC stub for {{}}: {{}}\", \"{target}\", input);\n}}\n"
        )
