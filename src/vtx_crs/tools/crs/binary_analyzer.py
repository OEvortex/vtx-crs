"""Binary static analysis tool: objdump, nm, strings, readelf, ELF/PE/Mach-O parsing."""

from __future__ import annotations

import asyncio
import re
import subprocess
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

from vtx_crs.core import FindingStatus, Severity, VulnerabilityFinding, get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


class BinaryAnalyzeParams(BaseModel):
    path: str = ""
    repo_path: str = ""
    analysis_type: str = "full"  # "full" | "symbols" | "strings" | "sections" | "imports"


class BinaryAnalyzerTool(BaseTool[BinaryAnalyzeParams]):
    name = "binary_analyze"
    description = (
        "Static analysis on a binary file (ELF/PE/Mach-O): symbols, imports, exports, "
        "strings, sections, architecture, and security hardening flags. Use this when "
        "source code is not available or when analyzing compiled artifacts."
    )
    params = BinaryAnalyzeParams
    mutating = False
    prompt_guidelines = (
        "Call binary_analyze when source code is unavailable or you need to inspect a compiled binary.",
        "Look for dangerous symbols (system, exec, strcpy, sprintf, gets), missing protections (NX, PIE, RELRO), "
        "and interesting strings (credentials, URLs, debug messages).",
    )

    async def execute(
        self, params: BinaryAnalyzeParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        # Defensive: params.path is the binary file; repo_path is cwd hint. Don't use resolve_repo_path which expects repo semantics.
        if params.path:
            target = Path(params.path)
            if not target.is_absolute():
                base = Path(params.repo_path) if params.repo_path else Path(_case_manager.active_case.repo_path) if _case_manager.active_case.repo_path else Path.cwd()
                target = (base / target).resolve() if base.exists() else target.resolve()
        else:
            target = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not target.exists() or not target.is_file():
            return ToolResult(
                success=False,
                result=f"Binary path does not exist or is not a file: {target}",
                ui_summary="Invalid binary path",
                ui_details="",
            )

        results: dict = {
            "path": str(target),
            "size": target.stat().st_size,
            "analysis_type": params.analysis_type,
        }

        sections: list[str] = []
        findings: list[dict] = []

        # File type detection
        file_type = self._detect_file_type(target)
        results["file_type"] = file_type

        # Architecture
        arch = self._get_arch(target, file_type)
        if arch:
            results["architecture"] = arch

        # Security hardening flags
        hardening = self._check_hardening(target, file_type)
        results["hardening"] = hardening
        if hardening.get("nx_disabled"):
            findings.append(
                {
                    "severity": "high",
                    "cwe": "CWE-119",
                    "title": "NX bit disabled",
                    "detail": "Binary may execute stack/heap memory",
                }
            )
        if hardening.get("pie_disabled") and file_type == "elf":
            findings.append(
                {
                    "severity": "medium",
                    "cwe": "CWE-110",
                    "title": "PIE/ASLR disabled",
                    "detail": "Binary loaded at fixed address",
                }
            )
        if hardening.get("relro") == "none":
            findings.append(
                {
                    "severity": "medium",
                    "cwe": "CWE-119",
                    "title": "RELRO disabled",
                    "detail": "GOT overwritable",
                }
            )
        if hardening.get("canary") == "none":
            findings.append(
                {
                    "severity": "high",
                    "cwe": "CWE-121",
                    "title": "Stack canary missing",
                    "detail": "Buffer overflow detection disabled",
                }
            )

        # Symbols
        if params.analysis_type in ("full", "symbols"):
            symbols = self._get_symbols(target, file_type)
            results["symbols"] = symbols
            dangerous_syms = self._check_dangerous_symbols(symbols)
            for sym in dangerous_syms:
                sev = "high" if sym["danger"] == "critical" else "medium"
                cwe = "CWE-78" if sym["name"] in ("system", "exec", "popen") else "CWE-120"
                findings.append(
                    {
                        "severity": sev,
                        "cwe": cwe,
                        "title": f"Dangerous symbol: {sym['name']}",
                        "detail": sym["reason"],
                    }
                )

        # Imports
        if params.analysis_type in ("full", "imports"):
            imports = self._get_imports(target, file_type)
            results["imports"] = imports

        # Strings
        if params.analysis_type in ("full", "strings"):
            strings = self._get_strings(target)
            results["strings_count"] = len(strings)
            interesting = self._check_interesting_strings(strings)
            findings.extend(interesting)

        sections.append(f"## Binary Analysis: {target.name}")
        sections.append(f"- File type: {file_type}")
        sections.append(f"- Size: {results['size']:,} bytes")
        sections.append(
            f"- Hardening: NX={hardening.get('nx', 'unknown')} PIE={hardening.get('pie', 'unknown')} RELRO={hardening.get('relro', 'unknown')} Canary={hardening.get('canary', 'unknown')}"
        )
        sections.append(
            f"- Dangerous symbols: {len([s for s in results.get('symbols', {}).get('exported', []) if any(d in s.lower() for d in ('system', 'exec', 'strcpy', 'sprintf', 'gets', 'scanf', 'strcat'))])}"
        )
        sections.append(
            f"- Interesting strings: {len([f for f in findings if f.get('title', '').startswith('Interesting string')])}"
        )

        if findings:
            sections.append("")
            sections.append("## Findings")
            for f in findings:
                sections.append(
                    f"- [{f.get('severity', 'medium').upper()}] {f.get('title')}: {f.get('detail')}"
                )
        # Persist binary findings to case so case_manager shows them (fixes ghost 0-findings)
        if findings:
            case = _case_manager.active_case
            if not case.repo_path:
                try:
                    case.repo_path = str(target.parent.resolve())
                except Exception:
                    pass
            for f in findings:
                vf = VulnerabilityFinding(
                    title=f.get("title", "Binary finding"),
                    description=f.get("detail", ""),
                    severity=Severity.from_str(f.get("severity", "medium")),
                    cwe_id=f.get("cwe", ""),
                    confidence=0.7,
                    file_path=str(target),
                    evidence=[f.get("detail", "")],
                    remediation="Harden binary: enable missing mitigations, remove dangerous symbols, review strings.",
                    status=FindingStatus.OPEN,
                    source="binary_analyze",
                    metadata={"binary": str(target), "finding": f},
                )
                case.add_finding(vf)
            _case_manager.save_active()
            sections.append(f"\n_Persisted {len(findings)} binary finding(s) to case {case.case_id}_")

        text = "\n".join(sections)
        return ToolResult(
            success=True,
            result=text,
            ui_summary=f"Analyzed {target.name}: {len(findings)} finding(s) -> case {_case_manager.active_case.case_id}",
            ui_details=text,
        )

    def _detect_file_type(self, path: Path) -> str:
        try:
            header = path.read_bytes()[:16]
            if header[:4] == b"\x7fELF":
                return "elf"
            if header[:2] == b"MZ":
                return "pe"
            if header[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
                return "macho"
        except Exception:
            pass
        return "unknown"

    def _get_arch(self, path: Path, file_type: str) -> str | None:
        try:
            if file_type == "elf":
                result = subprocess.run(
                    ["file", str(path)], capture_output=True, text=True, timeout=10
                )
                m = re.search(r"(x86-64|x86_64|i386|arm|aarch64|mips|ppc|riscv)", result.stdout, re.I)
                return m.group(1) if m else result.stdout.strip()[:80]
        except Exception:
            pass
        return None

    async def _run_cmd(self, cmd: list[str], timeout: int = 10) -> str:
        """Non-blocking wrapper for subprocess (fix: don't block event loop)."""
        try:
            proc = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True, timeout=timeout)
            stdout = proc.stdout
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            return stdout or ""
        except Exception:
            return ""

    def _check_hardening(self, path: Path, file_type: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "nx": "unknown",
            "pie": "unknown",
            "relro": "unknown",
            "canary": "unknown",
        }
        if file_type != "elf":
            return result
        try:
            out = subprocess.run(
                ["readelf", "-W", "-l", str(path)], capture_output=True, text=True, timeout=10
            ).stdout
            if "GNU_STACK" in out:
                # RAPTOR-style: check RWE flags accurately
                m = re.search(r"GNU_STACK[^\\n]*\s([RWE ]+)\s*$", out, re.M)
                flags = m.group(1) if m else ""
                if "E" in flags:
                    result["nx"] = "disabled"
                    result["nx_disabled"] = True
                elif "RWE" in out or "RW" in flags:
                    result["nx"] = "enabled"
                else:
                    result["nx"] = "enabled"
            # RELRO: check for BIND_NOW as full RELRO (oss-crs style)
            if "GNU_RELRO" in out:
                if "BIND_NOW" in out or "FLAGS_1" in out:
                    result["relro"] = "full"
                else:
                    result["relro"] = "partial"
            else:
                result["relro"] = "none"
            out2 = subprocess.run(
                ["readelf", "-W", "-s", str(path)], capture_output=True, text=True, timeout=10
            ).stdout
            out_dyn = subprocess.run(
                ["readelf", "-W", "-d", str(path)], capture_output=True, text=True, timeout=10
            ).stdout
            if "__stack_chk_fail" in out2 or "__stack_chk_guard" in out2:
                result["canary"] = "enabled"
            else:
                result["canary"] = "none"
            # PIE: EXEC = no PIE, DYN with PIE flag; also check file header via readelf -h
            hdr = subprocess.run(["readelf", "-h", str(path)], capture_output=True, text=True, timeout=10).stdout
            if re.search(r"Type:\s*EXEC", hdr):
                result["pie"] = "disabled"
                result["pie_disabled"] = True
            elif re.search(r"Type:\s*DYN", hdr):
                # DYN could be PIE or shared lib; check for DF_1_PIE
                if "PIE" in hdr or "DF_1_PIE" in out_dyn or "FLAGS_1" in out_dyn:
                    result["pie"] = "enabled"
                else:
                    # Shared library — not PIE in executable sense
                    result["pie"] = "shared"
            else:
                result["pie"] = "enabled"
        except Exception:
            pass
        return result

    def _get_symbols(self, path: Path, file_type: str) -> dict:
        result = {"exported": [], "imported": []}
        try:
            if file_type == "elf":
                dyn = subprocess.run(
                    ["readelf", "--dyn-syms", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
                for m in re.finditer(
                    r"\s+(\d+):\s+([0-9a-fA-F]+)\s+\d+\s+(OBJECT|FUNC|NOTYPE)\s+(GLOBAL|LOCAL)\s+(DEFAULT|HIDDEN)\s+(\w+)",
                    dyn,
                ):
                    sym = m.group(6)
                    if "GLOBAL" in m.group(4) and m.group(5) == "DEFAULT":
                        result["exported"].append(sym)
                for m in re.finditer(
                    r"\s+(\d+):\s+([0-9a-fA-F]+)\s+\d+\s+(OBJECT|FUNC|NOTYPE)\s+(GLOBAL|LOCAL)\s+(UND|WEAK)\s+(\w+)",
                    dyn,
                ):
                    result["imported"].append(m.group(6))
            elif file_type == "pe":
                out = subprocess.run(
                    ["nm", "-g", "--defined-only", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
                result["exported"] = [
                    line.split()[-1] for line in out.splitlines() if line.strip()
                ]
        except Exception:
            pass
        return result

    def _get_imports(self, path: Path, file_type: str) -> list[str]:
        result = []
        try:
            if file_type == "elf":
                out = subprocess.run(
                    ["readelf", "--dyn-syms", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
                result = list(set(re.findall(r"UND\s+(\w+)", out)))
        except Exception:
            pass
        return result

    def _check_dangerous_symbols(self, symbols: dict) -> list[dict]:
        dangerous = {
            "system": ("critical", "executes shell commands"),
            "exec": ("critical", "executes programs"),
            "popen": ("high", "pipes to shell"),
            "strcpy": ("high", "unbounded copy"),
            "sprintf": ("high", "unbounded format write"),
            "gets": ("critical", "reads without length limit"),
            "scanf": ("medium", "unbounded input"),
            "strcat": ("high", "unbounded concatenation"),
            "memcpy": ("medium", "potential overflow if size miscalculated"),
        }
        hits = []
        all_syms = symbols.get("exported", []) + symbols.get("imported", [])
        for sym in all_syms:
            low = sym.lower()
            for name, (danger, reason) in dangerous.items():
                if name == low:
                    hits.append({"name": sym, "danger": danger, "reason": reason})
        return hits

    def _get_strings(self, path: Path) -> list[str]:
        strings_list = []
        try:
            out = subprocess.run(
                ["strings", "-a", str(path)], capture_output=True, text=True, timeout=30
            ).stdout
            strings_list = [s.strip() for s in out.splitlines() if len(s.strip()) > 3]
        except Exception:
            pass
        return strings_list

    def _check_interesting_strings(self, strings_list: list[str]) -> list[dict]:
        findings = []
        patterns = [
            (r"[a-zA-Z0-9+/]{40,}={0,2}", "base64 blob", "medium"),
            (r"password\s*[=:]\s*\S+", "password literal", "high"),
            (r"api[_-]?key\s*[=:]\s*\S+", "API key literal", "high"),
            (r"https?://[^\s]+", "URL", "low"),
            (r"/[a-zA-Z0-9_/-]{3,100}", "filesystem path", "low"),
            (
                r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*?\b(?:FROM|WHERE|INTO)\b",
                "SQL query",
                "medium",
            ),
            (r"<script|javascript:|onerror\s*=|onload\s*=", "potential XSS", "medium"),
        ]
        for s in strings_list:
            for pat, title, sev in patterns:
                if re.search(pat, s, re.I):
                    findings.append(
                        {
                            "severity": sev,
                            "title": f"Interesting string: {title}",
                            "detail": s[:200],
                        }
                    )
                    break
        return findings


__all__ = ["BinaryAnalyzerTool"]
