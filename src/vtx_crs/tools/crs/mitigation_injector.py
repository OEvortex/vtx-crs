"""Inject compile-time or runtime mitigations into the project.

For now this tool supports scaffolding mitigations via source edits or by
writing configuration files (e.g., stack canaries, ASLR, NX, FORTIFY_SOURCE
flags, or safe-build wrappers).
"""

from __future__ import annotations

import asyncio
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


class MitigationInjectParams(BaseModel):
    repo_path: str = ""
    mitigation: str = "stack_canary"  # stack_canary | aslr | nx | fortify | safe_build_wrapper
    target: str = ""
    dry_run: bool = False


class MitigationInjectorTool(BaseTool[MitigationInjectParams]):
    name = "mitigation_inject"
    description = (
        "Inject a compile-time or runtime mitigation into the project. "
        "Supported mitigations include stack canaries, ASLR, NX, FORTIFY_SOURCE, "
        "and safe-build wrappers. Returns the suggested changes for the model to "
        "apply via patch_apply or manual edits."
    )
    params = MitigationInjectParams
    mutating = True
    prompt_guidelines = (
        "Run mitigation_inject after patch_validate passes to harden the fix.",
        "Prefer project-native build flags (Makefile, CMake, Cargo.toml).",
        "Do not introduce mitigations that break existing tests without confirming the break.",
    )

    async def execute(
        self, params: MitigationInjectParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        mitigation = params.mitigation.lower().replace("-", "_")
        target = params.target or str(repo)

        guidance = self._guidance(mitigation, repo, params.dry_run)

        if not params.dry_run:
            written = self._apply_guidance(repo, mitigation, guidance)
            if written:
                guidance += [
                    "",
                    f"Files written: {', '.join(written)}",
                    "Run build_runner and test_runner to verify.",
                ]

        result_text = "\n".join(guidance)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"mitigation_inject: {mitigation}",
            ui_details=result_text,
        )

    @staticmethod
    def _guidance(mitigation: str, repo: Path, dry_run: bool) -> list[str]:
        if mitigation == "stack_canary":
            return [
                "Stack canary mitigation:",
                "",
                "  C/C++: add -fstack-protector-strong (or -fstack-protector-all) to CFLAGS.",
                "  Rust: stack protection is enabled by default; ensure no 'no-stack-protector' attributes.",
                "  Go: no direct flag; rely on Go runtime bounds checks.",
                "",
                "Suggested edits:",
                f"  - Makefile/CMakeLists.txt: append -fstack-protector-strong to CFLAGS.",
                f"  - If no Makefile, create a wrapper compile script in {repo}/scripts/.",
            ]
        if mitigation == "fortify":
            return [
                "FORTIFY_SOURCE mitigation:",
                "",
                "  Add -D_FORTIFY_SOURCE=2 and -O2 (or higher) to CFLAGS.",
                "  This enables compile-time buffer overflow checks for common libc calls.",
                "",
                "Suggested edits:",
                "  - Append -D_FORTIFY_SOURCE=2 -O2 to build flags.",
                "  - Verify with: echo | gcc -dM -E - | grep _FORTIFY_SOURCE",
            ]
        if mitigation == "nx" or mitigation == "nx_bit":
            return [
                "NX (non-executable memory) mitigation:",
                "",
                "  Add -z noexecstack to LDFLAGS.",
                "  Ensure no JIT pages or inline assembly requires executable heap.",
                "",
                "Suggested edits:",
                "  - Append -z noexecstack to linker flags.",
            ]
        if mitigation == "aslr":
            return [
                "ASLR guidance:",
                "",
                "  This is typically an OS/runtime setting, not a source change.",
                "  For Linux: /proc/sys/kernel/randomize_va_space = 2",
                "  For containers: ensure --security-opt=no-new-privileges is not set to off.",
                "",
                "Suggested edits:",
                "  - Document ASLR requirements in README/SECURITY.md.",
                "  - Do not disable ASLR in test harnesses unless absolutely necessary.",
            ]
        if mitigation == "safe_build_wrapper":
            return [
                "Safe-build wrapper:",
                "",
                "  Create a wrapper script that enables hardening flags by default.",
                f"  Write it to {repo}/scripts/build-safe.sh.",
                "",
                "Suggested contents:",
                "  CFLAGS='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2'",
                "  LDFLAGS='-z noexecstack'",
                "  make $@",
            ]
        return [
            f"Unknown mitigation: {mitigation}",
            "Supported: stack_canary, fortify, nx, aslr, safe_build_wrapper.",
        ]

    @staticmethod
    def _apply_guidance(repo: Path, mitigation: str, guidance: list[str]) -> list[str]:
        written: list[str] = []
        if mitigation == "safe_build_wrapper":
            script = repo / "scripts" / "build-safe.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\n"
                'CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2" '
                'LDFLAGS="-z noexecstack" '
                'make "$@"\n',
                encoding="utf-8",
            )
            script.chmod(0o755)
            written.append(str(script))
        return written
