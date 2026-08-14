"""Professional CRS report generator (Markdown + JSON)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from .case import CrsCase


class CrsReport:
    """Generates a professional, auditable security report from a CrsCase."""

    SEVERITY_ORDER: ClassVar[dict[str, int]] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    def __init__(self, case: CrsCase, executive_summary: str = "") -> None:
        self.case = case
        self.executive_summary = executive_summary
        self.generated_at = datetime.now(UTC).isoformat()

    # ---- data -------------------------------------------------------------

    def _build_report_data(self) -> dict[str, Any]:
        case = self.case
        findings = sorted(
            case.findings.values(), key=lambda f: self.SEVERITY_ORDER.get(f.severity.value, 9)
        )
        report = {
            "report": {
                "title": case.title,
                "case_id": case.case_id,
                "repository": case.repo_path or "N/A",
                "status": case.status,
                "generated_at": self.generated_at,
                "engagement_period": {"started": case.created_at, "last_updated": case.updated_at},
            },
            "executive_summary": self.executive_summary or self._generate_executive_summary(),
            "scope_and_methodology": (
                "Autonomous cyber-reasoning pipeline: repository mapping, static pattern analysis "
                "(CWE-mapped), known-vulnerability dependency scanning (OSV), manual data-flow "
                "review, minimal patch generation and application, build verification, regression "
                "testing, and post-patch security validation."
            ),
            "summary": case.summary(),
            "findings": [f.to_dict() for f in findings],
            "patches": [p.to_dict() for p in case.patches.values()],
            "build_results": case.build_results,
            "test_results": case.test_results,
            "validation_results": case.validation_results,
            "timeline": list(case.timeline),
        }
        return report

    def _generate_executive_summary(self) -> str:
        case = self.case
        findings = list(case.findings.values())
        by_sev = case.summary()["findings_by_severity"]
        open_findings = [f for f in findings if f.status.value in ("open", "review")]
        fixed = [f for f in findings if f.status.value in ("patched", "fixed")]
        lines = [
            f"This report covers an autonomous security assessment of "
            f"`{case.repo_path or 'the target repository'}` "
            f"({case.case_id}).",
            "",
        ]
        if findings:
            lines.append(
                f"{len(findings)} finding(s) were identified "
                f"({by_sev.get('critical', 0)} critical, {by_sev.get('high', 0)} high, "
                f"{by_sev.get('medium', 0)} medium, {by_sev.get('low', 0)} low, "
                f"{by_sev.get('info', 0)} info)."
            )
        if fixed:
            lines.append(f"{len(fixed)} finding(s) have been remediated and verified.")
        if open_findings:
            lines.append(f"{len(open_findings)} finding(s) remain open and require follow-up.")
        if case.build_results.get("exit_code") == 0:
            lines.append("The project builds successfully after patching.")
        if case.test_results.get("failed", 0) == 0 and "passed" in case.test_results:
            lines.append("All regression tests pass.")
        lines.append(f"Case status: {case.status}. See the detailed sections below for evidence.")
        return " ".join(lines)

    # ---- markdown ---------------------------------------------------------

    def to_markdown(self) -> str:
        data = self._build_report_data()
        r = data["report"]
        lines = [
            f"# {r['title']}",
            "",
            "| | |",
            "|---|---|",
            f"| **Case ID** | {r['case_id']} |",
            f"| **Repository** | {r['repository']} |",
            f"| **Status** | {r['status']} |",
            f"| **Generated** | {r['generated_at']} |",
            "",
            "## Executive Summary",
            "",
            data["executive_summary"],
            "",
            "## 1. Scope & Methodology",
            "",
            data["scope_and_methodology"],
            "",
            "## 2. Engagement Summary",
            "",
        ]
        summary = data["summary"]
        lines.append("| Metric | Value |")
        lines.append("|---|---|")
        lines.append(f"| Findings | {summary['findings_count']} |")
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| Severity: {sev} | {summary['findings_by_severity'][sev]} |")
        lines.append(f"| Patches recorded | {summary['patches_count']} |")
        lines.append(f"| Patches applied | {summary['patches_applied']} |")
        build_exit = summary.get("build_exit")
        lines.append(f"| Build exit code | {build_exit if build_exit is not None else 'N/A'} |")
        lines.append(
            f"| Tests passed / failed | {summary.get('tests_passed') or 0} "
            f"/ {summary.get('tests_failed') or 0} |"
        )
        lines.append("")

        findings = data["findings"]
        if findings:
            lines.append("## 3. Findings")
            lines.append("")
            lines.append("| ID | Severity | CWE | Location | Title | Status |")
            lines.append("|---|---|---|---|---|---|")
            for f in findings:
                loc = f"{f['file_path']}:{f['line_start']}" if f["file_path"] else "—"
                lines.append(
                    f"| {f['id']} | {f['severity']} | {f['cwe_id'] or '—'} | "
                    f"`{loc}` | {f['title']} | {f['status']} |"
                )
            lines.append("")
            lines.append("### Finding details")
            lines.append("")
            for f in findings:
                lines.append(f"#### {f['id']} — {f['title']}")
                lines.append("")
                lines.append(
                    f"- **Severity:** {f['severity']} "
                    f"(CVSS {f['cvss_score'] if f['cvss_score'] is not None else 'N/A'}, "
                    f"confidence {f['confidence']:.0%})"
                )
                if f["cwe_id"]:
                    lines.append(f"- **CWE:** {f['cwe_id']}")
                if f["file_path"]:
                    loc = f"{f['file_path']}:{f['line_start']}"
                    if f["line_end"]:
                        loc = f"{loc}-{f['line_end']}"
                    lines.append(f"- **Location:** `{loc}`")
                lines.append(f"- **Status:** {f['status']}")
                lines.append("")
                lines.append(f"**Description:** {f['description']}")
                lines.append("")
                if f["code_snippet"]:
                    lines.append("```")
                    lines.append(f["code_snippet"])
                    lines.append("```")
                    lines.append("")
                if f["evidence"]:
                    lines.append("**Evidence:**")
                    lines.append("")
                    for ev in f["evidence"]:
                        lines.append(f"- {ev}")
                    lines.append("")
                lines.append(f"**Remediation:** {f['remediation'] or '—'}")
                lines.append("")

        patches = data["patches"]
        if patches:
            lines.append("## 4. Patches Applied")
            lines.append("")
            for p in patches:
                lines.append(f"### {p['id']} — {p['summary'] or 'Patch'}")
                lines.append("")
                lines.append(
                    f"- **Status:** {p['status']} | **Verification:** {p['verification']}"
                )
                if p["finding_ids"]:
                    lines.append(f"- **Fixes findings:** {', '.join(p['finding_ids'])}")
                if p["changed_files"]:
                    lines.append(f"- **Files:** {', '.join(p['changed_files'])}")
                if p["apply_message"]:
                    lines.append(f"- **Apply message:** {p['apply_message']}")
                lines.append("")
                if p["diff"]:
                    lines.append("```diff")
                    lines.append(p["diff"])
                    lines.append("```")
                    lines.append("")

        build = data["build_results"]
        if build:
            lines.append("## 5. Build Results")
            lines.append("")
            lines.append(f"- **Command:** `{build.get('command', 'N/A')}`")
            lines.append(f"- **Exit code:** {build.get('exit_code')}")
            lines.append(f"- **Duration:** {build.get('duration_seconds', 'N/A')}s")
            lines.append("")
            output = (build.get("output") or "").strip()
            if output:
                lines.append("```")
                lines.append(output[-4000:])
                lines.append("```")
                lines.append("")

        tests = data["test_results"]
        if tests:
            lines.append("## 6. Regression Test Results")
            lines.append("")
            lines.append(f"- **Command:** `{tests.get('command', 'N/A')}`")
            lines.append(
                f"- **Passed:** {tests.get('passed', 0)} | "
                f"**Failed:** {tests.get('failed', 0)} | **Total:** {tests.get('total', 0)}"
            )
            lines.append(f"- **Exit code:** {tests.get('exit_code')}")
            lines.append("")
            output = (tests.get("output") or "").strip()
            if output:
                lines.append("```")
                lines.append(output[-4000:])
                lines.append("```")
                lines.append("")

        validation = data["validation_results"]
        if validation:
            lines.append("## 7. Security Validation (Proof of Fix)")
            lines.append("")
            lines.append(f"- **Summary:** {validation.get('summary', 'N/A')}")
            lines.append(f"- **Command:** `{validation.get('command', 'N/A')}`")
            lines.append(f"- **Exit code:** {validation.get('exit_code')}")
            if validation.get("details"):
                lines.append("")
                lines.append("```")
                lines.append(str(validation.get("details"))[-4000:])
                lines.append("```")
            lines.append("")

        lines.append("## 8. Conclusion")
        lines.append("")
        lines.append(data["executive_summary"])
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("_Generated autonomously by vtx-crs._")
        lines.append("")
        return "\n".join(lines)

    # ---- json / io --------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self._build_report_data(), indent=indent, default=str)

    def write(self, output_dir: str | Path) -> dict[str, Path]:
        """Write report.md and report.json into ``output_dir``; returns paths."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        md_path = out / "report.md"
        json_path = out / "report.json"
        md_path.write_text(self.to_markdown(), encoding="utf-8")
        json_path.write_text(self.to_json(), encoding="utf-8")
        return {"markdown": md_path, "json": json_path}


__all__ = ["CrsReport"]
