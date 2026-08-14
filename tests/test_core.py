from vtx_crs.core import (
    CaseManager,
    CrsCase,
    CrsReport,
    FindingStatus,
    PatchRecord,
    PatchStatus,
    Severity,
    VerificationStatus,
    VulnerabilityFinding,
)


def test_finding_roundtrip() -> None:
    finding = VulnerabilityFinding(
        title="SQL injection",
        description="Query built by concatenation",
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        confidence=0.8,
        file_path="app/db.py",
        line_start=12,
        line_end=14,
        remediation="Use parameterized queries",
        source="patterns",
    )
    data = finding.to_dict()
    restored = VulnerabilityFinding.from_dict(data)
    assert restored.id == finding.id
    assert restored.title == finding.title
    assert restored.severity == Severity.HIGH
    assert restored.status == FindingStatus.OPEN
    assert restored.cwe_id == "CWE-89"


def test_case_roundtrip(tmp_path) -> None:
    case = CrsCase(title="Test engagement", repo_path="/tmp/example")
    case.add_finding(VulnerabilityFinding(title="XSS", severity=Severity.MEDIUM, cwe_id="CWE-79"))
    case.add_patch(
        PatchRecord(
            diff="--- a/x\n+++ b/x\n",
            finding_ids=["F-x"],
            status=PatchStatus.APPLIED,
            verification=VerificationStatus.PASSED,
        )
    )
    case.record_build({"command": "make", "exit_code": 0})
    case.record_tests({"command": "pytest", "passed": 12, "failed": 0, "total": 12})
    case.add_timeline("pipeline complete")

    data = case.to_dict()
    restored = CrsCase.from_dict(data)
    assert restored.case_id == case.case_id
    assert len(restored.findings) == 1
    assert len(restored.patches) == 1
    assert restored.build_results["exit_code"] == 0
    assert restored.test_results["passed"] == 12
    assert restored.timeline[-1].endswith("pipeline complete")
    assert restored.summary()["findings_count"] == 1
    assert restored.summary()["findings_by_severity"]["medium"] == 1


def test_case_manager_persists(tmp_path) -> None:
    manager = CaseManager(storage_dir=str(tmp_path / "cases"))
    case = manager.create_case(title="T1", repo_path="/repo/a")
    case.add_finding(VulnerabilityFinding(title="F1"))
    manager.save_active()

    manager2 = CaseManager(storage_dir=str(tmp_path / "cases"))
    assert len(manager2.list_cases()) == 1
    loaded = manager2.switch_case(case.case_id)
    assert loaded is not None
    assert len(loaded.findings) == 1


def test_report_generation(tmp_path) -> None:
    case = CrsCase(title="Engagement", repo_path="/repo/x")
    case.add_finding(
        VulnerabilityFinding(
            title="Command injection",
            severity=Severity.CRITICAL,
            cwe_id="CWE-78",
            file_path="cli.py",
            line_start=3,
            remediation="Use shell=False",
        )
    )
    case.record_build({"command": "make", "exit_code": 0})
    case.record_tests({"command": "pytest -q", "passed": 10, "failed": 0, "total": 10})
    case.update_finding_status(next(iter(case.findings)), FindingStatus.PATCHED)
    case.record_validation({"summary": "PoC fails as expected", "exit_code": 1})

    report = CrsReport(case, executive_summary="Engagement summary text.")
    md = report.to_markdown()
    assert "# Engag" in md
    assert "Command injection" in md
    assert "CWE-78" in md
    assert "Engagement summary text." in md
    assert "10 / 0" in md

    report.write(tmp_path / "out")
    assert (tmp_path / "out" / "report.md").exists()
    assert (tmp_path / "out" / "report.json").exists()
    assert "findings" in (tmp_path / "out" / "report.json").read_text(encoding="utf-8")
