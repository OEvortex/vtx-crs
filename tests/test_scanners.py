from pathlib import Path

from vtx_crs.core import Severity
from vtx_crs.tools.crs.dependency_scanner import DependencyScannerTool
from vtx_crs.tools.crs.vuln_scanner import VulnScannerTool

VULNERABLE_PY = '''"""Sample app."""
import os
import hashlib

def run(user_cmd):
    result = os.system(user_cmd)
    return result

password = "super-secret-pass"

def get_hash(data):
    return hashlib.md5(data).hexdigest()
'''


def test_pattern_scanner_detects_known_classes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(VULNERABLE_PY, encoding="utf-8")
    tool = VulnScannerTool()
    findings = tool._scan_patterns(tmp_path, {".py"}, Severity.INFO, None)

    names = {f.title.lower() for f in findings}
    assert "os system popen" in names
    assert "hardcoded secret" in names
    assert "weak hash" in names
    # Language scoping: PHP-only rules must not fire on Python sources.
    assert "php shell exec" not in names
    # Line numbers point into the fixture.
    os_finding = next(f for f in findings if f.title.lower() == "os system popen")
    assert os_finding.line_start >= 5
    assert os_finding.file_path == "app.py"
    assert os_finding.cwe_id == "CWE-78"


def test_pattern_scanner_skips_min_severity(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(VULNERABLE_PY, encoding="utf-8")
    tool = VulnScannerTool()
    findings = tool._scan_patterns(tmp_path, {".py"}, Severity.HIGH, None)
    assert all(f.severity.value in ("high", "critical") for f in findings)


def test_parse_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3.0.0\n# comment\ndjango\n", encoding="utf-8"
    )
    packages = DependencyScannerTool._parse_manifest(tmp_path / "requirements.txt", "PyPI")
    assert ("PyPI", "requests", "2.31.0") in packages
    assert ("PyPI", "flask", "3.0.0") in packages
    assert len(packages) == 2


def test_parse_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["httpx>=0.27.0", "pydantic==2.12.5"]\n', encoding="utf-8"
    )
    packages = DependencyScannerTool._parse_manifest(tmp_path / "pyproject.toml", "PyPI")
    assert ("PyPI", "httpx", "0.27.0") in packages
    assert ("PyPI", "pydantic", "2.12.5") in packages


def test_parse_package_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.17.21", "react": "18.2.0"}}', encoding="utf-8"
    )
    packages = DependencyScannerTool._parse_manifest(tmp_path / "package.json", "npm")
    assert ("npm", "lodash", "4.17.21") in packages
    assert ("npm", "react", "18.2.0") in packages


def test_cvss_vector_parsing() -> None:
    # S:U with AC/UI metrics present — exercises prefix-collision handling.
    score = DependencyScannerTool._cvss_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None
    assert score >= 9.0  # classic critical RCE vector
    assert Severity.from_cvss(score) == Severity.CRITICAL


def test_cvss_low_impact_vector() -> None:
    score = DependencyScannerTool._cvss_from_vector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N")
    assert score is not None
    assert 0.0 < score < 4.0
    assert Severity.from_cvss(score) in (Severity.LOW, Severity.MEDIUM)


def test_cvss_invalid_vector() -> None:
    assert DependencyScannerTool._cvss_from_vector("not-a-vector") is None


def test_parse_package_json_ranges(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"axios": ">=1.2.0 <2.0.0", "next": "14.2.5 || 14.3.0"}}',
        encoding="utf-8",
    )
    packages = DependencyScannerTool._parse_manifest(tmp_path / "package.json", "npm")
    assert ("npm", "axios", "1.2.0") in packages
    assert ("npm", "next", "14.2.5") in packages
