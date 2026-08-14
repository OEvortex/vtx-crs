"""CRS case model: a structured audit trail for one repository analysis run."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from .finding import FindingStatus, VulnerabilityFinding
from .patch import PatchRecord


class CrsCase:
    def __init__(self, case_id: str = "", title: str = "", repo_path: str = "") -> None:
        now = datetime.now(UTC)
        self.case_id = case_id or now.strftime("%Y%m%d_%H%M%S")
        self.title = title or f"CRS engagement {self.case_id}"
        self.repo_path = repo_path
        self.created_at = now.isoformat()
        self.updated_at = self.created_at
        self.status: str = "open"
        self.findings: dict[str, VulnerabilityFinding] = {}
        self.patches: dict[str, PatchRecord] = {}
        self.build_results: dict[str, Any] = {}
        self.test_results: dict[str, Any] = {}
        self.validation_results: dict[str, Any] = {}
        self.timeline: list[str] = []
        self.notes: list[str] = []

    # ---- timeline / notes -------------------------------------------------

    def add_timeline(self, event: str) -> None:
        self.timeline.append(f"[{datetime.now(UTC).isoformat()}] {event}")
        self.updated_at = datetime.now(UTC).isoformat()

    def add_note(self, note: str) -> None:
        self.notes.append(f"[{datetime.now(UTC).isoformat()}] {note}")
        self.updated_at = datetime.now(UTC).isoformat()

    def close(self) -> None:
        self.status = "closed"
        self.add_timeline("Case closed")

    # ---- findings ---------------------------------------------------------

    def add_finding(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        self.findings[finding.id] = finding
        self.add_timeline(
            f"Finding {finding.id} added: {finding.title} ({finding.severity.value})"
        )
        return finding

    def get_finding(self, finding_id: str) -> VulnerabilityFinding | None:
        return self.findings.get(finding_id)

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> bool:
        finding = self.findings.get(finding_id)
        if finding is None:
            return False
        finding.status = status
        finding.touch()
        self.add_timeline(f"Finding {finding_id} status -> {status.value}")
        return True

    # ---- patches ----------------------------------------------------------

    def add_patch(self, patch: PatchRecord) -> PatchRecord:
        self.patches[patch.id] = patch
        self.add_timeline(f"Patch {patch.id} recorded ({patch.status.value})")
        return patch

    def get_patch(self, patch_id: str) -> PatchRecord | None:
        return self.patches.get(patch_id)

    # ---- results ----------------------------------------------------------

    def record_build(self, result: dict[str, Any]) -> None:
        self.build_results = result
        self.add_timeline(f"Build finished: exit={result.get('exit_code')}")

    def record_tests(self, result: dict[str, Any]) -> None:
        self.test_results = result
        self.add_timeline(
            f"Tests finished: passed={result.get('passed')} failed={result.get('failed')}"
        )

    def record_validation(self, result: dict[str, Any]) -> None:
        self.validation_results = result
        self.add_timeline(f"Security validation finished: {result.get('summary', '')}")

    # ---- serialization ----------------------------------------------------

    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "repo_path": self.repo_path,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "findings_count": len(self.findings),
            "findings_by_severity": {
                sev: sum(1 for f in self.findings.values() if f.severity.value == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "findings_by_status": {
                status: sum(1 for f in self.findings.values() if f.status.value == status)
                for status in ("open", "patched", "fixed", "false_positive", "wont_fix", "review")
            },
            "patches_count": len(self.patches),
            "patches_applied": sum(
                1 for p in self.patches.values() if p.status.value == "applied"
            ),
            "build_exit": self.build_results.get("exit_code"),
            "tests_passed": self.test_results.get("passed"),
            "tests_failed": self.test_results.get("failed"),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "repo_path": self.repo_path,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "timeline": list(self.timeline),
            "notes": list(self.notes),
            "findings": [f.to_dict() for f in self.findings.values()],
            "patches": [p.to_dict() for p in self.patches.values()],
            "build_results": self.build_results,
            "test_results": self.test_results,
            "validation_results": self.validation_results,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CrsCase:
        case = cls(
            case_id=data.get("case_id", ""),
            title=data.get("title", ""),
            repo_path=data.get("repo_path", ""),
        )
        case.created_at = data.get("created_at", case.created_at)
        case.updated_at = data.get("updated_at", case.updated_at)
        case.status = data.get("status", "open")
        case.timeline = list(data.get("timeline", []))
        case.notes = list(data.get("notes", []))
        for fdata in data.get("findings", []):
            finding = VulnerabilityFinding.from_dict(fdata)
            case.findings[finding.id] = finding
        for pdata in data.get("patches", []):
            patch = PatchRecord.from_dict(pdata)
            case.patches[patch.id] = patch
        case.build_results = dict(data.get("build_results", {}))
        case.test_results = dict(data.get("test_results", {}))
        case.validation_results = dict(data.get("validation_results", {}))
        return case


class CaseManager:
    def __init__(self, storage_dir: str | None = None) -> None:
        if storage_dir is None:
            storage_dir = str(Path.home() / ".vtx_crs" / "cases")
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._cases: dict[str, CrsCase] = {}
        self._active_case_id: str | None = None
        self._load_all()

    @property
    def active_case(self) -> CrsCase:
        if self._active_case_id is None or self._active_case_id not in self._cases:
            case = CrsCase()
            self._cases[case.case_id] = case
            self._active_case_id = case.case_id
        return self._cases[self._active_case_id]

    @active_case.setter
    def active_case(self, case: CrsCase) -> None:
        self._cases[case.case_id] = case
        self._active_case_id = case.case_id

    def create_case(self, title: str = "", repo_path: str = "") -> CrsCase:
        case = CrsCase(title=title, repo_path=repo_path)
        self._cases[case.case_id] = case
        self._active_case_id = case.case_id
        self._save(case)
        return case

    def switch_case(self, case_id: str) -> CrsCase | None:
        if case_id in self._cases:
            self._active_case_id = case_id
            return self._cases[case_id]
        loaded = self._load(case_id)
        if loaded:
            self._cases[loaded.case_id] = loaded
            self._active_case_id = loaded.case_id
        return loaded

    def list_cases(self) -> list[dict[str, Any]]:
        self._load_all()
        return [c.summary() for c in self._cases.values()]

    def save_active(self) -> None:
        if self._active_case_id and self._active_case_id in self._cases:
            self._save(self._cases[self._active_case_id])

    def _save(self, case: CrsCase) -> None:
        path = self.storage_dir / f"{case.case_id}.json"
        path.write_text(case.to_json(), encoding="utf-8")

    def _load(self, case_id: str) -> CrsCase | None:
        path = self.storage_dir / f"{case_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return CrsCase.from_dict(data)
        except Exception:
            return None

    def _load_all(self) -> None:
        for path in self.storage_dir.glob("*.json"):
            if path.stem not in self._cases:
                loaded = self._load(path.stem)
                if loaded:
                    self._cases[loaded.case_id] = loaded


@lru_cache(maxsize=1)
def get_case_manager() -> CaseManager:
    """Return the single shared CaseManager instance used by all CRS tools.

    A single instance guarantees findings, patches, and validation results
    accumulate in the same active case across the whole pipeline.
    """
    return CaseManager()


__all__ = ["CaseManager", "CrsCase", "get_case_manager"]
