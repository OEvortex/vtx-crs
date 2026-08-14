"""Dependency scanner: keyless known-vulnerability lookup via the OSV API.

Parses the project's dependency manifests (requirements.txt, pyproject.toml,
package.json, Cargo.toml, go.mod) and queries OSV for each pinned package.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from pathlib import Path

import httpx
from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import FindingStatus, Severity, VulnerabilityFinding, get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


# Manifest -> (ecosystem, parser returning (name, version) pairs)
def _cvss_exploitability(av: float, ac: float, pr: float, ui: float) -> float:
    return 8.22 * av * ac * pr * ui


PARSERS: dict[str, str] = {
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
    "Cargo.toml": "crates.io",
    "go.mod": "Go",
}

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|<|>)\s*([0-9][0-9A-Za-z.\-]*)")


class DependencyScanParams(BaseModel):
    repo_path: str = ""
    ecosystems: list[str] = []  # empty = auto-detect
    save_findings: bool = True
    timeout_seconds: int = 30


class DependencyScannerTool(BaseTool[DependencyScanParams]):
    name = "dependency_scan"
    description = (
        "Scan the project's pinned dependencies for known vulnerabilities via the OSV API "
        "(keyless). Parses requirements.txt, pyproject.toml, package.json, Cargo.toml and "
        "go.mod. Returns CVE/OSV ids, severity, and fixed versions."
    )
    params = DependencyScanParams
    mutating = False
    prompt_guidelines = (
        "Run dependency_scan once the build system is known (step 1).",
        "Use the returned fixed versions in patch remediation for dependency findings.",
    )

    async def execute(
        self, params: DependencyScanParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ToolResult(
                success=False,
                result=f"Repository path does not exist: {repo}",
                ui_summary="Invalid repository path",
                ui_details="",
            )

        packages = self._collect_packages(repo, set(params.ecosystems))
        if not packages:
            return ToolResult(
                success=False,
                result="No dependency manifests with pinned versions found.",
                ui_summary="No dependencies found",
                ui_details="",
            )

        findings, errors = await self._query_osv(packages, params.timeout_seconds)
        if params.save_findings:
            case = _case_manager.active_case
            for f in findings:
                case.add_finding(f)
            _case_manager.save_active()

        lines = [
            f"Dependency scan: {len(packages)} package(s) checked, "
            f"{len(findings)} known vulnerability(ies).",
            "",
        ]
        if findings:
            for f in findings:
                lines.append(
                    f"- {f.title} [{f.severity.value}] (CWE: {f.cwe_id or 'n/a'}) — "
                    f"{f.remediation}"
                )
        else:
            lines.append("No known vulnerabilities found in pinned versions.")
        if errors:
            lines.append("")
            lines.append(f"Note: {errors} package(s) could not be queried (network/parse errors).")

        result_text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(findings)} known vuln(s) in {len(packages)} deps",
            ui_details=result_text,
        )

    # ---- manifest parsing -------------------------------------------------

    @staticmethod
    def _collect_packages(repo: Path, ecosystems: set[str]) -> list[tuple[str, str, str]]:
        """Return [(ecosystem, name, version), ...] from manifests in repo."""
        packages: list[tuple[str, str, str]] = []
        for filename, eco in PARSERS.items():
            if ecosystems and eco not in ecosystems:
                continue
            path = repo / filename
            if not path.exists():
                continue
            try:
                packages.extend(DependencyScannerTool._parse_manifest(path, eco))
            except Exception:
                continue
        return packages

    @staticmethod
    def _parse_manifest(path: Path, eco: str) -> list[tuple[str, str, str]]:
        if path.name == "requirements.txt":
            return DependencyScannerTool._parse_requirements(path, eco)
        if path.name == "pyproject.toml":
            return DependencyScannerTool._parse_pyproject(path, eco)
        if path.name == "package.json":
            return DependencyScannerTool._parse_package_json(path, eco)
        if path.name == "Cargo.toml":
            return DependencyScannerTool._parse_cargo(path, eco)
        if path.name == "go.mod":
            return DependencyScannerTool._parse_gomod(path, eco)
        return []

    @staticmethod
    def _parse_requirements(path: Path, eco: str) -> list[tuple[str, str, str]]:
        out = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            m = _REQ_LINE.match(line)
            if m:
                out.append((eco, m.group(1).lower(), m.group(2)))
        return out

    @staticmethod
    def _parse_pyproject(path: Path, eco: str) -> list[tuple[str, str, str]]:
        import tomllib

        out = []
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except tomllib.TOMLDecodeError:
            return out
        dep_lists: list[list[str]] = []
        project = data.get("project") or {}
        dep_lists.append(list(project.get("dependencies") or []))
        for group in (project.get("optional-dependencies") or {}).values():
            dep_lists.append(list(group))
        poetry = (data.get("tool") or {}).get("poetry") or {}
        dep_lists.append(list(poetry.get("dependencies") or {}))
        for group in (poetry.get("group") or {}).values():
            for _, deps in (group or {}).items():
                if isinstance(deps, dict):
                    dep_lists.append(list(deps.get("dependencies") or []))
        for dep_list in dep_lists:
            for dep in dep_list:
                if isinstance(dep, dict):
                    continue
                m = _REQ_LINE.match(dep.strip())
                if m:
                    out.append((eco, m.group(1).lower(), m.group(2)))
        return out

    @staticmethod
    def _parse_package_json(path: Path, eco: str) -> list[tuple[str, str, str]]:
        out = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return out
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            for name, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                version = spec.strip().lstrip("^~>=< ")
                # Drop ranges like ">=1.2.3 <2.0.0" and "1.2.3 || 1.3.0".
                version = re.split(r"\s*\|\||\s+", version)[0].strip()
                if re.match(r"^\d", version):
                    out.append((eco, name, version))
        return out

    @staticmethod
    def _parse_cargo(path: Path, eco: str) -> list[tuple[str, str, str]]:
        out = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        section_re = re.compile(
            r"^\[(dependencies|dev-dependencies|build-dependencies)\]", re.MULTILINE
        )
        # Very small parser: find section starts, capture "name = \"x.y.z\"" lines.
        matches = list(section_re.finditer(content))
        for i, m in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            body = content[m.end() : end]
            for dep_line in body.splitlines():
                dm = re.match(r'^\s*([A-Za-z0-9_\-]+)\s*=\s*"([0-9][^"]*)"', dep_line)
                if dm:
                    version = dm.group(2).strip()
                    if re.match(r"^\d", version):
                        out.append((eco, dm.group(1), version))
        return out

    @staticmethod
    def _parse_gomod(path: Path, eco: str) -> list[tuple[str, str, str]]:
        out = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("require") and "(" not in line:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "require":
                    out.append((eco, parts[1], parts[2]))
            elif line.startswith("\t") and "/" in line and not line.strip().startswith("//"):
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^v\d", parts[1]):
                    out.append((eco, parts[0], parts[1]))
        return out

    # ---- OSV queries ------------------------------------------------------

    async def _query_osv(
        self, packages: list[tuple[str, str, str]], timeout: int
    ) -> tuple[list[VulnerabilityFinding], int]:
        findings: list[VulnerabilityFinding] = []
        errors = 0
        seen: set[tuple[str, str]] = set()

        async with httpx.AsyncClient(timeout=timeout) as client:
            for eco, name, version in packages:
                try:
                    resp = await client.post(
                        OSV_QUERY_URL,
                        json={"package": {"ecosystem": eco, "name": name}, "version": version},
                    )
                    if resp.status_code == 404 or resp.status_code == 400:
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    errors += 1
                    continue

                for vuln in data.get("vulns") or []:
                    vuln_id = vuln.get("id", "OSV-unknown")
                    dedup = (vuln_id, f"{eco}:{name}")
                    if dedup in seen:
                        continue
                    seen.add(dedup)

                    summary = vuln.get("summary") or vuln.get("details", "")[:200]
                    severity, cvss = self._osv_severity(vuln)
                    cwes = []
                    db_specific = vuln.get("database_specific") or {}
                    for c in db_specific.get("cwe_ids") or []:
                        cwes.append(c if str(c).startswith("CWE-") else f"CWE-{c}")
                    aliases = vuln.get("aliases") or []
                    fixed = self._fixed_version(vuln, name)

                    title = f"{name} {version}: {vuln_id}"
                    remediation = (
                        f"Upgrade {name} to {fixed}"
                        if fixed
                        else f"Upgrade {name} to a patched version"
                    )
                    evidence = [f"OSV advisory: {vuln_id}"]
                    if aliases:
                        evidence.append(f"Aliases: {', '.join(aliases)}")
                    evidence.append(f"Affected package: {name}@{version} ({eco})")
                    if summary:
                        evidence.append(summary)

                    findings.append(
                        VulnerabilityFinding(
                            title=title,
                            description=f"Known vulnerability in dependency {name}@{version} ({eco}): {summary}",
                            severity=severity,
                            cwe_id=cwes[0] if cwes else "",
                            cvss_score=cvss,
                            confidence=0.85,
                            file_path=f"dependency: {name}@{version}",
                            remediation=remediation,
                            status=FindingStatus.OPEN,
                            source="osv",
                            evidence=evidence,
                            metadata={
                                "osv_id": vuln_id,
                                "ecosystem": eco,
                                "package": name,
                                "version": version,
                                "aliases": aliases,
                                "fixed_version": fixed or "",
                            },
                        )
                    )

        findings.sort(
            key=lambda f: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    f.severity.value, 9
                ),
                f.title,
            )
        )
        return findings, errors

    @staticmethod
    def _osv_severity(vuln: dict) -> tuple[Severity, float | None]:
        db_specific = vuln.get("database_specific") or {}
        sev_str = str(db_specific.get("severity", "")).upper()
        for sev in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
            if sev in sev_str:
                mapped = "medium" if sev == "MODERATE" else sev.lower()
                return Severity.from_str(mapped), None

        for s in vuln.get("severity") or []:
            if s.get("type") == "CVSS_V3":
                vector = s.get("score", "")
                score = DependencyScannerTool._cvss_from_vector(vector)
                if score is not None:
                    return Severity.from_cvss(score), score
        return Severity.MEDIUM, None

    @staticmethod
    def _cvss_from_vector(vector: str) -> float | None:
        """Compute the CVSS v3.1 base score from a vector string.

        Each component is extracted with a dedicated regex group so metric
        names like "AC:", "UI:", and the "SS:" inside "CVSS:" can never be
        confused with the component prefixes.
        """
        m = re.search(
            r"CVSS:3\.\d/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/"
            r"S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])",
            vector,
            re.IGNORECASE,
        )
        if not m:
            return None

        av, ac, pr, ui, scope, c, i, a = (g.upper() for g in m.groups())
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[av]
        ac = {"L": 0.77, "H": 0.44}[ac]
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}[pr]
        ui = {"N": 0.85, "R": 0.62}[ui]

        imp = {"N": 0, "L": 0.22, "H": 0.56}
        isc_base = 1 - (1 - imp[c]) * (1 - imp[i]) * (1 - imp[a])
        if scope == "U":
            impact = 6.42 * isc_base
            base = impact + _cvss_exploitability(av, ac, pr, ui)
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
            base = 1.08 * (impact + _cvss_exploitability(av, ac, pr, ui))
        return math.ceil(min(base, 10.0) * 10) / 10

    @staticmethod
    def _fixed_version(vuln: dict, package: str) -> str:
        for affected in vuln.get("affected") or []:
            if affected.get("package", {}).get("name") != package:
                continue
            for rng in affected.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if "fixed" in ev and ev.get("fixed") not in (None, "*"):
                        return str(ev["fixed"])
        return ""
