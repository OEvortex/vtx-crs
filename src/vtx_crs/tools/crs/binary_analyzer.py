"""Binary static analysis tool: objdump, nm, strings, readelf, ELF/PE/Mach-O parsing."""

from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import get_case_manager

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
        target = resolve_repo_path(params.path, params.repo_path)
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

        text = "\n".join(sections)
        return ToolResult(
            success=True,
            result=text,
            ui_summary=f"Analyzed {target.name}: {len(findings)} finding(s)",
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
                m = re.search(r"(x86-64|x86_64|i386|arm|aarch64|mips|ppc)", result.stdout, re.I)
                return m.group(1) if m else None
        except Exception:
            pass
        return None

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
                m = re.search(r"GNU_STACK.*\s([RWE]+)\s", out)
                if m and "E" not in m.group(1):
                    result["nx"] = "enabled"
                else:
                    result["nx"] = "disabled"
                    result["nx_disabled"] = True
            if "GNU_RELRO" in out:
                result["relro"] = "partial" if out.count("GNU_RELRO") > 1 else "full"
            else:
                result["relro"] = "none"
            out2 = subprocess.run(
                ["readelf", "-W", "-s", str(path)], capture_output=True, text=True, timeout=10
            ).stdout
            if "__stack_chk_fail" in out2 or "__stack_chk_guard" in out2:
                result["canary"] = "enabled"
            else:
                result["canary"] = "none"
            if re.search(r"Type:\s*EXEC", out):
                result["pie"] = "disabled"
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
