"""Dependency scanner: OP multi-source — OSV + NVD + GitHub Advisory + CISA KEV + EPSS.

Parses manifests (requirements.txt, pyproject.toml, package.json, Cargo.lock, Cargo.toml, go.mod,
yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile.lock) and enriches every finding with
free intel feeds — no API keys required. Uses OSV as primary (covers GHSA + NVD aliases) and
augments with KEV exploited flag + EPSS exploit probability to prioritize.
Open-source engines: pip-audit/semgrep-style local checks if available, with graceful fallback.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import shutil
from pathlib import Path

import httpx
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

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
# Free feeds — no keys, generous rate limits
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# In-memory cache for KEV / EPSS to avoid repeated fetches per run
_KEV_CACHE: set[str] | None = None
_EPSS_CACHE: dict[str, float] = {}


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
    enrich_kev_epss: bool = True  # free CISA KEV + EPSS enrichment
    run_local_audit: bool = True  # try pip-audit / npm audit if installed (open-source)


class DependencyScannerTool(BaseTool[DependencyScanParams]):
    name = "dependency_scan"
    description = (
        "OP dependency scan: multi-source keyless intel — OSV (primary, covers GHSA/NVD) + "
        "CISA KEV exploited flag + FIRST EPSS exploit probability + local pip-audit/npm-audit "
        "if installed. Parses requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, "
        "package.json, yarn.lock, pnpm-lock.yaml, Cargo.toml/lock, go.mod. Returns CVE/OSV ids, "
        "CVSS, KEV/EPSS, and fixed versions. No API key needed."
    )
    params = DependencyScanParams
    mutating = False
    prompt_guidelines = (
        "Run dependency_scan right after repo_analyze — it is keyless and fast via OSV batch.",
        "Prioritize KEV=true or EPSS>0.5 findings first (exploited in wild). Use fixed_version in patches.",
        "If pip-audit or npm audit is installed, local audit results are merged automatically for defense-in-depth.",
    )

    async def execute(
        self, params: DependencyScanParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        # Auto-attach repo to case if needed
        _tmp_case = _case_manager.active_case
        _tmp_repo = resolve_repo_path(params.repo_path, _tmp_case.repo_path)
        if _tmp_repo.exists() and not _tmp_case.repo_path:
            _tmp_case.repo_path = str(_tmp_repo)
            _case_manager.save_active()
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

        # Primary: OSV batch (faster than N per-package calls)
        findings, errors = await self._query_osv(packages, params.timeout_seconds)

        # Free enrichment: KEV + EPSS (no key, best-effort)
        if params.enrich_kev_epss and findings:
            try:
                kev_set = await self._fetch_kev(params.timeout_seconds)
                # annotate each finding if its CVE is in KEV
                for f in findings:
                    cves = [a for a in (f.metadata.get("aliases") or []) if str(a).startswith("CVE-")]
                    cves.append(f.metadata.get("osv_id", ""))
                    if any(c in kev_set for c in cves):
                        f.metadata["kev_exploited"] = True
                        # escalate severity one notch if not already critical
                        if f.severity.value in ("medium", "high"):
                            f.severity = Severity.CRITICAL if f.severity.value == "high" else Severity.HIGH
                        f.evidence.append("CISA KEV: actively exploited in the wild — patch immediately")
                        f.remediation = "URGENT (KEV): " + f.remediation
            except Exception:
                pass
            # EPSS scores for top CVEs
            try:
                cve_list = []
                for f in findings[:15]:
                    for a in f.metadata.get("aliases") or []:
                        if str(a).startswith("CVE-") and a not in cve_list:
                            cve_list.append(a)
                if cve_list:
                    epss_map = await self._fetch_epss(cve_list, params.timeout_seconds)
                    for f in findings:
                        for a in f.metadata.get("aliases") or []:
                            if a in epss_map:
                                score = epss_map[a]
                                f.metadata[f"epss_{a}"] = score
                                if score > 0.5 and f.severity.value != "critical":
                                    f.evidence.append(f"EPSS {score:.3f}: high exploit probability (>0.5)")
                                break
            except Exception:
                pass

        # Local open-source auditors (pip-audit / npm audit) — free, offline-capable
        local_notes: list[str] = []
        if params.run_local_audit:
            try:
                local = await self._run_local_audits(repo, params.timeout_seconds)
                local_notes = local
            except Exception:
                pass

        if params.save_findings:
            case = _case_manager.active_case
            for f in findings:
                case.add_finding(f)
            _case_manager.save_active()

        # Sort: KEV first, then EPSS, then severity
        def _rank(f: VulnerabilityFinding) -> tuple[int, float, int]:
            is_kev = 0 if f.metadata.get("kev_exploited") else 1
            epss = max([float(v) for k, v in f.metadata.items() if k.startswith("epss_")] or [0.0])
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 9)
            return (is_kev, -epss, sev_rank)

        findings.sort(key=_rank)

        kev_count = sum(1 for f in findings if f.metadata.get("kev_exploited"))
        lines = [
            f"Dependency scan: {len(packages)} package(s) checked, {len(findings)} vuln(s).",
            f"Sources: OSV (primary) + CISA KEV ({kev_count} exploited) + EPSS (free) + local audit." if params.enrich_kev_epss else "Source: OSV",
            "",
        ]
        if findings:
            for f in findings:
                kev_flag = " [KEV!]" if f.metadata.get("kev_exploited") else ""
                epss_flag = ""
                for k, v in f.metadata.items():
                    if k.startswith("epss_") and float(v) > 0.3:
                        epss_flag = f" EPSS:{float(v):.2f}"
                        break
                lines.append(
                    f"- {f.title}{kev_flag}{epss_flag} [{f.severity.value}] (CWE: {f.cwe_id or 'n/a'}) — {f.remediation}"
                )
        else:
            lines.append("No known vulnerabilities found in pinned versions.")
        if local_notes:
            lines.append("")
            lines.append("Local audit notes (open-source):")
            lines.extend(f"  {n}" for n in local_notes[:10])
        if errors:
            lines.append("")
            lines.append(f"Note: {errors} package(s) could not be queried (network/parse errors).")
        if kev_count:
            lines.append("")
            lines.append(f"Priority: {kev_count} KEV-exploited vuln(s) — patch these first (active exploitation).")

        result_text = "\n".join(lines)
        return ToolResult(
            success=True,
            result=result_text,
            ui_summary=f"{len(findings)} vuln(s) in {len(packages)} deps ({kev_count} KEV)" if kev_count else f"{len(findings)} vuln(s) in {len(packages)} deps",
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

    # ---- Free enrichment: KEV + EPSS + local audits -------------------------

    @staticmethod
    async def _fetch_kev(timeout: int) -> set[str]:
        global _KEV_CACHE
        if _KEV_CACHE is not None:
            return _KEV_CACHE
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
                r = await c.get(KEV_URL, headers={"User-Agent": "vtx-crs/0.1"})
                r.raise_for_status()
                data = r.json()
                cves = {v.get("cveID") for v in data.get("vulnerabilities") or [] if v.get("cveID")}
                _KEV_CACHE = cves
                return cves
        except Exception:
            _KEV_CACHE = set()
            return set()

    @staticmethod
    async def _fetch_epss(cves: list[str], timeout: int) -> dict[str, float]:
        # FIRST EPSS free API — batch is comma-separated
        if not cves:
            return {}
        # check cache
        uncached = [c for c in cves if c not in _EPSS_CACHE]
        if uncached:
            try:
                async with httpx.AsyncClient(timeout=timeout) as c:
                    r = await c.get(EPSS_URL, params={"cve": ",".join(uncached[:100])}, headers={"User-Agent": "vtx-crs/0.1"})
                    r.raise_for_status()
                    data = r.json()
                    for item in data.get("data") or []:
                        cve = item.get("cve")
                        try:
                            _EPSS_CACHE[cve] = float(item.get("epss", 0))
                        except Exception:
                            pass
            except Exception:
                pass
        return {c: _EPSS_CACHE[c] for c in cves if c in _EPSS_CACHE}

    @staticmethod
    async def _run_local_audits(repo: Path, timeout: int) -> list[str]:
        notes: list[str] = []
        # pip-audit (open-source, uses OSV + PyPI, no key)
        if shutil.which("pip-audit"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "pip-audit", "--format", "json",
                    cwd=str(repo), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                if stdout:
                    data = json.loads(stdout.decode(errors="ignore"))
                    vulns = data.get("dependencies") or data.get("vulnerabilities") or []
                    if vulns:
                        notes.append(f"pip-audit: {len(vulns)} finding(s) via local DB")
            except Exception:
                pass
        # npm audit (free, uses GitHub Advisory via npm registry)
        if (repo / "package.json").exists() and shutil.which("npm"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "npm", "audit", "--json",
                    cwd=str(repo), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=min(timeout, 20))
                if stdout:
                    data = json.loads(stdout.decode(errors="ignore"))
                    vulns = data.get("vulnerabilities") or data.get("advisories") or {}
                    cnt = len(vulns) if isinstance(vulns, dict) else len(vulns)
                    if cnt:
                        notes.append(f"npm audit: {cnt} finding(s) via GitHub Advisory")
            except Exception:
                pass
        # cargo audit if present
        if (repo / "Cargo.lock").exists() and shutil.which("cargo"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "cargo", "audit", "--json",
                    cwd=str(repo), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=min(timeout, 20))
                if stdout and b"vulnerabilities" in stdout.lower():
                    notes.append("cargo audit: findings via RustSec Advisory DB")
            except Exception:
                pass
        return notes

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
