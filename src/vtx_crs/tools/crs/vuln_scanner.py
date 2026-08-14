"""Static vulnerability scanner: CWE-mapped pattern analysis over source files.

Heuristic by design — every hit must be confirmed by reading the code around
it (the model is instructed to do this). Findings are recorded in the active
CRS case for the final report.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import FindingStatus, Severity, VulnerabilityFinding, get_case_manager

from ._common import MAX_FILE_BYTES, iter_source_files, resolve_repo_path

_case_manager = get_case_manager()

DEFAULT_SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".c",
    ".cpp",
    ".cc",
    ".h",
    ".hpp",
    ".php",
    ".rb",
    ".sh",
    ".bash",
    ".cs",
    ".swift",
    ".scala",
    ".sql",
    ".lua",
    ".ex",
    ".exs",
    ".vue",
}

# Language groups used to scope rules to relevant file types.
_LANG_PY = {"python"}
_LANG_JS = {"javascript", "typescript"}
_LANG_JAVA = {"java"}
_LANG_PHP = {"php"}

# Each rule: name, cwe, severity, regex, description, remediation, confidence,
# and optional "languages" restricting which file types it applies to.
PATTERN_RULES: list[dict] = [
    {
        "name": "subprocess_shell_true",
        "cwe": "CWE-78",
        "severity": "high",
        "languages": _LANG_PY,
        "pattern": r"subprocess\.(?:run|call|Popen|check_call|check_output)\([^)]*shell\s*=\s*True",
        "description": "subprocess invoked with shell=True. If any part of the command string includes untrusted input, this is OS command injection.",
        "remediation": "Call subprocess with shell=False and pass the command as an argument list; validate/allowlist inputs.",
        "confidence": 0.6,
    },
    {
        "name": "os_system_popen",
        "cwe": "CWE-78",
        "severity": "high",
        "languages": _LANG_PY,
        "pattern": r"\bos\.(?:system|popen)\s*\(",
        "description": "os.system()/os.popen() executes a string through the shell. Untrusted input in the string yields command injection.",
        "remediation": "Replace with subprocess.run([...], shell=False) using an argument list; never concatenate user input into shell strings.",
        "confidence": 0.7,
    },
    {
        "name": "eval_exec",
        "cwe": "CWE-95",
        "severity": "medium",
        "languages": {"python", "javascript", "typescript", "php", "ruby"},
        "pattern": r"\b(?:eval|exec)\s*\(",
        "description": "Dynamic code execution via eval()/exec(). If input is user-controlled, this enables arbitrary code execution.",
        "remediation": "Avoid eval/exec. Use a safe parser or allowlist of permitted operations; never evaluate untrusted input.",
        "confidence": 0.5,
    },
    {
        "name": "pickle_loads",
        "cwe": "CWE-502",
        "severity": "high",
        "languages": _LANG_PY,
        "pattern": r"\b(?:pickle|cloudpickle|cPickle)\.loads?\s*\(",
        "description": "Unsafe deserialization with pickle. Pickles can execute arbitrary code when loaded from untrusted sources.",
        "remediation": "Prefer safe formats (JSON with strict schema validation). If pickles must be accepted, authenticate and verify their source.",
        "confidence": 0.7,
    },
    {
        "name": "yaml_load",
        "cwe": "CWE-502",
        "severity": "medium",
        "languages": _LANG_PY,
        "pattern": r"\byaml\.load\s*\(\s*(?!.*SafeLoader)",
        "description": "yaml.load() without an explicit SafeLoader can instantiate arbitrary Python objects.",
        "remediation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        "confidence": 0.6,
    },
    {
        "name": "sql_built_string",
        "cwe": "CWE-89",
        "severity": "high",
        "pattern": r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^;]{0,200}?(?:f[\"']|\"|')?\s*(?:\+|%|\.format\(|f[\"']\{)",
        "description": "SQL query built by string concatenation/interpolation. User-controlled fragments can inject SQL.",
        "remediation": "Use parameterized queries (cursor.execute with ? or %s placeholders, ORM query builders).",
        "confidence": 0.4,
    },
    {
        "name": "sqlite_concat",
        "cwe": "CWE-89",
        "severity": "high",
        "pattern": r"execute\s*\(\s*(?:f[\"']|[\"'])[^\"']*(\{|%|\+|\"\s*\+)",
        "description": "Database execute() call with an interpolated/concatenated query string.",
        "remediation": "Pass query parameters as a separate arguments tuple to execute(); never inline them into the SQL string.",
        "confidence": 0.5,
    },
    {
        "name": "path_traversal",
        "cwe": "CWE-22",
        "severity": "medium",
        "pattern": r"(?:open|os\.open|Path\(|join)\s*\([^)]*\.\.(?:/|\\)|f?[\"'][^\"']*\.\./(?!\w*[.\w]*\.[a-z]{2,4}\b)",
        "description": "Possible path traversal: file access built with .. segments. If an input reaches here, arbitrary file read/write is possible.",
        "remediation": "Resolve the path and verify it stays within the intended base directory (os.path.realpath + prefix check); use an allowlist.",
        "confidence": 0.4,
    },
    {
        "name": "hardcoded_aws_key",
        "cwe": "CWE-798",
        "severity": "critical",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "description": "Hardcoded AWS access key ID in source. Keys in code are a credential leak.",
        "remediation": "Remove the key, rotate it, and load credentials from the environment or a secret manager.",
        "confidence": 0.9,
    },
    {
        "name": "private_key",
        "cwe": "CWE-798",
        "severity": "critical",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
        "description": "Private key material committed to the repository.",
        "remediation": "Remove the key, revoke/rotate it, and store secrets outside the repo.",
        "confidence": 0.95,
    },
    {
        "name": "hardcoded_secret",
        "cwe": "CWE-798",
        "severity": "medium",
        "pattern": r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*[\"'][^\"']{6,}[\"']",
        "description": "Possible hardcoded credential/secret literal in code.",
        "remediation": "Move secrets to environment variables or a secret store; never commit literals.",
        "confidence": 0.5,
    },
    {
        "name": "weak_hash",
        "cwe": "CWE-327",
        "severity": "medium",
        "pattern": r"(?:hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\(\s*[\"'](?:MD5|SHA-?1)[\"']|md5\(|sha1\()",
        "description": "Use of broken cryptographic hashes (MD5/SHA-1), unsafe for passwords or integrity.",
        "remediation": "Use SHA-256 or stronger; use a dedicated password hashing scheme (argon2, bcrypt, scrypt).",
        "confidence": 0.6,
    },
    {
        "name": "xss_innerhtml",
        "cwe": "CWE-79",
        "severity": "high",
        "languages": _LANG_JS,
        "pattern": r"\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML",
        "description": "DOM XSS sink: attacker-controlled data assigned into innerHTML / document.write is rendered unescaped.",
        "remediation": "Use textContent/innerText or escape/encode output; use framework auto-escaping; avoid dangerouslySetInnerHTML.",
        "confidence": 0.6,
    },
    {
        "name": "child_process_exec",
        "cwe": "CWE-78",
        "severity": "high",
        "languages": _LANG_JS,
        "pattern": r"(?:child_process\.)?(?:exec|execSync|spawn)\(\s*[\"'`]",
        "description": "Node.js child_process execution with a command string. Untrusted input yields command injection.",
        "remediation": "Use execFile/spawn with an argument array; validate inputs; avoid shell interpretation.",
        "confidence": 0.5,
    },
    {
        "name": "java_runtime_exec",
        "cwe": "CWE-78",
        "severity": "high",
        "languages": _LANG_JAVA,
        "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(",
        "description": "Java OS command execution. String-based exec with user input enables command injection.",
        "remediation": "Use ProcessBuilder with an argument list (never a concatenated string) and validate inputs.",
        "confidence": 0.6,
    },
    {
        "name": "java_deserialization",
        "cwe": "CWE-502",
        "severity": "high",
        "languages": _LANG_JAVA,
        "pattern": r"ObjectInputStream|readObject\s*\(",
        "description": "Java deserialization of untrusted streams can lead to remote code execution.",
        "remediation": "Avoid deserializing untrusted data; use allowlist-based deserialization filters (JEP 290) or safe formats.",
        "confidence": 0.5,
    },
    {
        "name": "php_shell_exec",
        "cwe": "CWE-78",
        "severity": "high",
        "languages": _LANG_PHP,
        "pattern": r"\b(?:shell_exec|passthru|proc_open|pcntl_exec)\s*\(|(?<![\w])system\s*\(",
        "description": "PHP shell execution functions. User input in these strings enables command injection.",
        "remediation": "Avoid shell functions; use escapeshellarg() on every argument or use a safe API.",
        "confidence": 0.6,
    },
    {
        "name": "php_include",
        "cwe": "CWE-98",
        "severity": "high",
        "languages": _LANG_PHP,
        "pattern": r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$",
        "description": "PHP file inclusion driven by a variable. Remote File Inclusion / Local File Inclusion if user-controlled.",
        "remediation": "Resolve and validate the included path against an allowlist; never let user input select files.",
        "confidence": 0.5,
    },
    {
        "name": "weak_random",
        "cwe": "CWE-330",
        "severity": "low",
        "pattern": r"\brandom\.(?:random|randint|choice|uniform)\(|Math\.random\(",
        "description": "Use of a non-cryptographic RNG. Not suitable for tokens, passwords, or security decisions.",
        "remediation": "Use secrets / os.urandom / crypto.getRandomValues for anything security-sensitive.",
        "confidence": 0.4,
    },
    {
        "name": "insecure_redirect",
        "cwe": "CWE-601",
        "severity": "medium",
        "pattern": r"(?:redirect|sendRedirect|Location)\s*[=(].*?(?:params|request|req|input|user|next)",
        "description": "Open redirect: destination built from request/user input without an allowlist.",
        "remediation": "Validate the redirect target against an allowlist of internal hosts.",
        "confidence": 0.3,
    },
]

# Map file extension -> language group.
_EXT_LANGUAGE = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "java",
    ".php": "php",
    ".rb": "ruby",
}


class VulnScanParams(BaseModel):
    repo_path: str = ""
    min_severity: str = "info"  # info | low | medium | high | critical
    include_exts: list[str] = []
    save_findings: bool = True


class VulnScannerTool(BaseTool[VulnScanParams]):
    name = "vuln_scan"
    description = (
        "Run CWE-mapped static pattern analysis over the repository source code to discover "
        "candidate security vulnerabilities (command injection, SQL injection, XSS, path "
        "traversal, unsafe deserialization, hardcoded secrets, weak crypto, and more). "
        "Hits are heuristics — confirm each one by reading the code before patching."
    )
    params = VulnScanParams
    mutating = False
    prompt_guidelines = (
        "Run vuln_scan after repo_analyze for the initial sweep.",
        "Confirm every hit by reading the surrounding code — trace the data flow to the sink.",
        "Pass save_findings=true (default) so findings are recorded in the case for the report.",
    )

    async def execute(
        self, params: VulnScanParams, cancel_event: asyncio.Event | None = None
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
        extensions = set(params.include_exts) or DEFAULT_SCAN_EXTENSIONS

        findings = self._scan_patterns(repo, extensions, min_sev, cancel_event)

        if not findings:
            return ToolResult(
                success=True,
                result=f"No pattern matches found in {repo}.",
                ui_summary="No matches",
                ui_details="",
            )

        if params.save_findings:
            case = _case_manager.active_case
            for f in findings:
                case.add_finding(f)
            _case_manager.save_active()

        summary_lines = [
            f"Pattern analysis complete: {len(findings)} candidate finding(s).",
            "",
            f"{'ID':<12} {'SEV':<9} {'CWE':<10} LOCATION",
            "-" * 70,
        ]
        for f in findings:
            loc = f"{f.file_path}:{f.line_start}" if f.file_path else "?"
            summary_lines.append(f"{f.id:<12} {f.severity.value:<9} {f.cwe_id:<10} {loc}")

        result_text = "\n".join(summary_lines)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(findings)} candidate finding(s)",
            ui_details=result_text,
        )

    def _scan_patterns(
        self,
        repo: Path,
        extensions: set[str],
        min_sev: Severity,
        cancel_event: asyncio.Event | None,
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        seen: set[tuple[str, str, int]] = set()
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_rank = severity_rank.get(min_sev.value, 4)

        for path in iter_source_files(repo, extensions):
            if cancel_event and cancel_event.is_set():
                break
            lang = _EXT_LANGUAGE.get(path.suffix.lower(), "")
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for rule in PATTERN_RULES:
                langs = rule.get("languages")
                if langs is not None and lang not in langs:
                    continue
                if severity_rank.get(rule["severity"], 4) > min_rank:
                    continue
                for m in re.finditer(rule["pattern"], content, re.IGNORECASE):
                    line_start = content.count("\n", 0, m.start()) + 1
                    dedup_key = (str(path.relative_to(repo)), rule["name"], line_start)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    line_end = line_start + content[m.start() : m.end()].count("\n")
                    findings.append(
                        VulnerabilityFinding(
                            title=rule["name"].replace("_", " ").title(),
                            description=rule["description"],
                            severity=Severity.from_str(rule["severity"]),
                            cwe_id=rule["cwe"],
                            confidence=rule["confidence"],
                            file_path=str(path.relative_to(repo)),
                            line_start=line_start,
                            line_end=line_end or line_start,
                            code_snippet=self._snippet(content, line_start),
                            remediation=rule["remediation"],
                            status=FindingStatus.OPEN,
                            source="patterns",
                            metadata={"pattern": rule["name"], "match": m.group(0)[:200]},
                        )
                    )

        findings.sort(
            key=lambda f: (severity_rank.get(f.severity.value, 9), f.file_path, f.line_start)
        )
        return findings

    @staticmethod
    def _snippet(content: str, line_start: int, before: int = 2, after: int = 2) -> str:
        lines = content.splitlines()
        lo = max(0, line_start - 1 - before)
        hi = min(len(lines), line_start - 1 + after + 1)
        return "\n".join(f"{i + 1:>5} | {lines[i]}" for i in range(lo, hi))
