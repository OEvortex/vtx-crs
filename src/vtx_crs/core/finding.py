"""Vulnerability finding model shared across the CRS pipeline."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @staticmethod
    def from_cvss(score: float | None) -> Severity:
        if score is None:
            return Severity.INFO
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 0.1:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def from_str(value: str) -> Severity:
        try:
            return Severity(value.lower())
        except ValueError:
            return Severity.INFO


class FindingStatus(StrEnum):
    OPEN = "open"
    PATCHED = "patched"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    REVIEW = "review"


@dataclass
class VulnerabilityFinding:
    """A single security finding with full audit trail."""

    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cwe_id: str = ""
    cvss_score: float | None = None
    confidence: float = 0.5
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    source: str = "manual"  # "patterns" | "dependencies" | "osv" | "manual"
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        if not self.id:
            ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            self.id = f"F-{ts}-{uuid.uuid4().hex[:6]}"

    def touch(self) -> None:
        self.updated_at = datetime.now(UTC).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "evidence": list(self.evidence),
            "remediation": self.remediation,
            "status": self.status.value,
            "source": self.source,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VulnerabilityFinding:
        f = cls(
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=Severity.from_str(data.get("severity", "medium")),
            cwe_id=data.get("cwe_id", ""),
            cvss_score=data.get("cvss_score"),
            confidence=float(data.get("confidence", 0.5)),
            file_path=data.get("file_path", ""),
            line_start=int(data.get("line_start", 0)),
            line_end=int(data.get("line_end", 0)),
            code_snippet=data.get("code_snippet", ""),
            evidence=list(data.get("evidence", [])),
            remediation=data.get("remediation", ""),
            status=FindingStatus(data.get("status", FindingStatus.OPEN.value))
            if data.get("status") in {s.value for s in FindingStatus}
            else FindingStatus.OPEN,
            source=data.get("source", "manual"),
            metadata=dict(data.get("metadata", {})),
            id=data.get("id", ""),
        )
        f.created_at = data.get("created_at", f.created_at)
        f.updated_at = data.get("updated_at", f.updated_at)
        return f


__all__ = ["FindingStatus", "Severity", "VulnerabilityFinding"]
