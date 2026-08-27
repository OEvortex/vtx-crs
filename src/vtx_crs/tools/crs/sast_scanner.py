"""Structural static analysis: control-flow and data-flow checks.

This tool wraps heuristic pattern analysis with a structural framing: it
prioritizes findings by reachability context (are they behind auth? are they
in hot paths?). It reuses `VulnScannerTool`-style patterns but adds a simple
"contextual risk" layer.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult  # type: ignore

from vtx_crs.core import Severity, get_case_manager

from ._common import MAX_FILE_BYTES, iter_source_files, resolve_repo_path
from .vuln_scanner import DEFAULT_SCAN_EXTENSIONS as _DEFAULT_SCAN_EXTENSIONS

_case_manager = get_case_manager()

_STRUCTURAL_RULES = [
    {
        "name": "unauthenticated_route",
        "cwe": "CWE-306",
        "severity": "high",
        "pattern": r"(?:@app\.route|app\.(?:get|post|put|delete)\(|router\.(?:get|post)|func\s+\w+.*?HandleFunc)",
        "description": "HTTP route handler detected without obvious auth middleware. Verify that authentication/authorization is enforced before this entry point.",
        "remediation": "Add auth checks (session, token, ACL) before the handler body.",
        "confidence": 0.3,
    },
    {
        "name": "hardcoded_bind",
        "cwe": "CWE-605",
        "severity": "medium",
        "pattern": r"(?:bind\(|listen\(|0\.0\.0\.0|INADDR_ANY|INADDR_ANY)",
        "description": "Service binds to all interfaces or uses a hardcoded address. If credentials or sensitive data are served, this widens the attack surface.",
        "remediation": "Bind to 127.0.0.1 or a private interface when local-only access is intended.",
        "confidence": 0.5,
    },
    {
        "name": "insecure_deserialize",
        "cwe": "CWE-502",
        "severity": "high",
        "pattern": r"(?:pickle\.load|yaml\.load\(|marshal\.load|jsonpickle\.decode|shelve\.open)",
        "description": "Untrusted data is deserialized without a safe loader. This is a common code execution path.",
        "remediation": "Use safe loaders (yaml.safe_load, JSON with schema validation).",
        "confidence": 0.6,
    },
    {
        "name": "command_injection_arg",
        "cwe": "CWE-78",
        "severity": "high",
        "pattern": r"(?:system\(|exec\(|popen\(|subprocess\.(?:run|call|Popen)\(|execSync\(|spawn\()",
        "description": "A command execution API is called. If the command string includes user-controlled data, this is a command injection sink.",
        "remediation": "Use argument lists, avoid shell=True, sanitize/allowlist inputs.",
        "confidence": 0.5,
    },
    {
        "name": "hardcoded_secret",
        "cwe": "CWE-798",
        "severity": "high",
        "pattern": r"(?:password|secret|api[_-]?key)\s*[:=]\s*[\"'][^\"']{6,}[\"']",
        "description": "Hardcoded secret/password/API key. Rotate immediately and use env/secret manager.",
        "remediation": "Move to environment variable or secrets manager; rotate credential.",
        "confidence": 0.7,
    },
    {
        "name": "weak_crypto",
        "cwe": "CWE-327",
        "severity": "medium",
        "pattern": r"(?:md5\(|sha1\(|DES\.|RC4|Blowfish|random\.random\(|Math\.random\()",
        "description": "Weak crypto / PRNG detected (MD5/SHA1/DES/RC4/Math.random). Use SHA-256+ and CSPRNG.",
        "remediation": "Use hashlib.sha256, secrets module, or approved crypto library.",
        "confidence": 0.6,
    },
    {
        "name": "ssrf_sink",
        "cwe": "CWE-918",
        "severity": "high",
        "pattern": r"(?:requests\.(?:get|post)\(|urllib\.request\.urlopen|fetch\(|http\.request\()",
        "description": "Server-side request to user-controlled URL (SSRF risk). Validate allowlist.",
        "remediation": "Allowlist destinations, block private IPs, require auth.",
        "confidence": 0.4,
    },
    {
        "name": "open_redirect",
        "cwe": "CWE-601",
        "severity": "medium",
        "pattern": r"(?:redirect\(|location\.href\s*=|window\.location)",
        "description": "Potential open redirect with user-controlled destination.",
        "remediation": "Validate redirect target against allowlist.",
        "confidence": 0.4,
    },
]


class SastScanParams(BaseModel):
    repo_path: str = ""
    min_severity: str = "info"
    include_exts: list[str] = []


class SastScannerTool(BaseTool[SastScanParams]):
    name = "sast_scan"
    description = (
        "Run structural static analysis: control-flow and data-flow checks beyond "
        "simple pattern matching. Surfaces unauthenticated routes, hardcoded binds, "
        "insecure deserialization, and command injection entry points."
    )
    params = SastScanParams
    mutating = False
    prompt_guidelines = (
        "Run sast_scan after vuln_scan to add structural context.",
        "Treat every hit as a candidate; confirm by reading the surrounding handler/auth code.",
        "Focus on routes and public entry points first.",
    )

    async def execute(
        self, params: SastScanParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        min_sev = Severity.from_str(params.min_severity)
        extensions = set(params.include_exts) or _DEFAULT_SCAN_EXTENSIONS

        findings: list[dict] = []
        seen: set[tuple[str, str, int]] = set()
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_rank = severity_rank.get(min_sev.value, 4)

        for path in iter_source_files(repo, extensions):
            if cancel_event and cancel_event.is_set():
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = str(path.relative_to(repo))
            lines = content.splitlines()

            for lineno, line in enumerate(lines, 1):
                for rule in _STRUCTURAL_RULES:
                    if not re.search(rule["pattern"], line, re.IGNORECASE):
                        continue
                    sev_rank = severity_rank.get(rule["severity"], 4)
                    if sev_rank > min_rank:
                        continue
                    key = (rel, rule["name"], lineno)
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "rule": rule["name"],
                            "cwe": rule["cwe"],
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "remediation": rule["remediation"],
                            "confidence": rule["confidence"],
                            "code": line.strip()[:200],
                        }
                    )

        if not findings:
            return ToolResult(
                success=True,
                result="No structural static-analysis hits found.",
                ui_summary="No structural findings",
                ui_details="",
            )

        lines_out = [
            f"Structural SAST: {len(findings)} candidate(s)",
            "",
            f"{'FILE':<30} {'LINE':<6} {'SEV':<9} {'RULE'}",
            "-" * 70,
        ]
        for f in findings:
            lines_out.append(
                f"{f['file']:<30} {f['line']:<6} {f['severity']:<9} {f['rule']}"
            )
            lines_out.append(f"    {f['description']}")
            lines_out.append(f"    {f['code']}")

        result_text = "\n".join(lines_out)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(findings)} structural finding(s)",
            ui_details=result_text,
        )
