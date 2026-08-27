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
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult  # type: ignore

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
        ext_map = {"python": "py", "py": "py", "c": "c", "rust": "rs", "rs": "rs", "go": "go", "js": "js"}
        ext = ext_map.get(poc_type, poc_type.split(".")[-1] if "." in poc_type else poc_type)
        target = Path(params.target_file).stem if params.target_file else "poc"
        out_file = output_dir / f"poc_{target}.{ext}"

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
        safe_target = target.replace("-", "_")
        if poc_type == "python":
            b64 = base64.b64encode(raw.encode()).decode()
            return (
                f'"""PoC for {target} — vtx-crs offensive proof (non-weaponized)."""\n'
                f'"""Reproduces: {target_file} with crash input."""\n\n'
                f"import subprocess, sys, base64\nfrom pathlib import Path\n\n"
                f"INPUT = base64.b64decode(\"{b64}\").decode('utf-8', errors='ignore')\n"
                f"INPUT_RAW = r\"{safe_input}\"\n\n\n"
                f"def main() -> int:\n"
                f"    # 1) Try direct import+call (defensive: validates in-process)\n"
                f"    try:\n"
                f"        import importlib.util\n"
                f"        tf = Path(r\"{target_file}\")\n"
                f"        if tf.exists() and tf.suffix == '.py':\n"
                f"            spec = importlib.util.spec_from_file_location('_poc_target', tf)\n"
                f"            m = importlib.util.module_from_spec(spec)\n"  # type: ignore
                f"            spec.loader.exec_module(m)  # type: ignore\n"
                f"            fn = getattr(m, '{safe_target}', None)\n"
                f"            if callable(fn):\n"
                f"                print(f'[PoC] calling {safe_target}({{INPUT!r}})')\n"
                f"                fn(INPUT)\n"
                f"                print('[PoC] no crash (patched or not vulnerable)')\n"
                f"                return 0\n"
                f"    except Exception as e:\n"
                f"        print(f'[PoC] direct call crashed: {{e}}', file=sys.stderr)\n"
                f"        import traceback; traceback.print_exc()\n"
                f"        return 1\n"
                f"    # 2) Fallback: subprocess execution\n"
                f"    target = Path(r\"{target_file}\")\n"
                f"    if not target.exists():\n"
                f"        print(f'Target not found: {{target}}', file=sys.stderr)\n"
                f"        return 2\n"
                f"    print('Running PoC via subprocess:', target)\n"
                f"    p = subprocess.run([sys.executable, str(target)], input=INPUT.encode(), capture_output=True, timeout=10)\n"
                f"    print(p.stdout.decode('utf-8', 'replace'))\n"
                f"    if p.stderr:\n"
                f"        print(p.stderr.decode('utf-8', 'replace'), file=sys.stderr)\n"
                f"    print(f'Exit code: {{p.returncode}}')\n"
                f"    return 1 if p.returncode != 0 else 0\n\n\n"
                f"if __name__ == '__main__':\n"
                f"    sys.exit(main())\n"
            )
        if poc_type == "c":
            hex_input = raw.encode("utf-8").hex()
            hex_bytes = ", ".join(f"0x{hex_input[i:i+2]}" for i in range(0, len(hex_input), 2)) if hex_input else "0x00"
            return (
                f'/* PoC for {target} — vtx-crs offensive (reproduces crash). */\n'
                f'/* Compile: gcc -g -O0 -o poc_{safe_target} poc_{safe_target}.c && ./poc_{safe_target} */\n\n'
                f"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdint.h>\n\n"
                f"extern int {safe_target}(const char *);\n"
                f"__attribute__((weak)) int {safe_target}(const char *s) {{ printf(\"[PoC] weak stub hit: %s\\n\", s); return 0; }}\n\n"
                f"static const uint8_t PAYLOAD[] = {{{hex_bytes}}};\n"
                f"static const char PAYLOAD_STR[] = \"{safe_input}\";\n\n"
                f"int main(void) {{\n"
                f"    char *buf = malloc(sizeof(PAYLOAD)+1);\n"
                f"    memcpy(buf, PAYLOAD, sizeof(PAYLOAD));\n"
                f"    buf[sizeof(PAYLOAD)]='\\0';\n"
                f"    printf(\"[PoC] calling {safe_target} with len=%zu\\n\", sizeof(PAYLOAD));\n"
                f"    int r = {safe_target}(buf);\n"
                f"    printf(\"[PoC] returned %d (no crash)\\n\", r);\n"
                f"    // Also try string literal path\n"
                f"    {safe_target}(PAYLOAD_STR);\n"
                f"    free(buf);\n"
                f"    return r;\n}}\n"
            )
        # rust / default
        safe_rust = raw.replace("\\", "\\\\").replace('"', '\\"')
        return (
            f'// PoC for {target} — vtx-crs offensive proof.\n'
            f'// Run: rustc poc_{safe_target}.rs -o poc_{safe_target} && ./poc_{safe_target}\n\n'
            f"fn target_call(input: &str) {{\n"
            f"    // Replace with actual {target} call from {target_file}\n"
            f"    println!(\"[PoC] calling {target} with {{:?}}\", input);\n"
            f"    let _ = input;\n}}\n\n"
            f"fn main() {{\n"
            f"    let input = r#\"{safe_rust}\"#;\n"
            f"    target_call(&input);\n"
            f"    println!(\"[PoC] done\");\n}}\n"
        )
