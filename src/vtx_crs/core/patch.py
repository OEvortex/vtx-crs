"""Patch record model tracking applied security patches and their verification."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class PatchStatus(StrEnum):
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    REVERTED = "reverted"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PatchRecord:
    diff: str
    finding_ids: list[str] = field(default_factory=list)
    summary: str = ""
    status: PatchStatus = PatchStatus.PENDING
    verification: VerificationStatus = VerificationStatus.UNVERIFIED
    changed_files: list[str] = field(default_factory=list)
    apply_message: str = ""
    id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    applied_at: str = ""
    verified_at: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            self.id = f"P-{ts}-{uuid.uuid4().hex[:6]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "diff": self.diff,
            "finding_ids": list(self.finding_ids),
            "status": self.status.value,
            "verification": self.verification.value,
            "changed_files": list(self.changed_files),
            "apply_message": self.apply_message,
            "created_at": self.created_at,
            "applied_at": self.applied_at,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PatchRecord:
        status = data.get("status", PatchStatus.PENDING.value)
        verification = data.get("verification", VerificationStatus.UNVERIFIED.value)
        p = cls(
            diff=data.get("diff", ""),
            finding_ids=list(data.get("finding_ids", [])),
            summary=data.get("summary", ""),
            status=(
                PatchStatus(status)
                if status in {s.value for s in PatchStatus}
                else PatchStatus.PENDING
            ),
            verification=(
                VerificationStatus(verification)
                if verification in {v.value for v in VerificationStatus}
                else VerificationStatus.UNVERIFIED
            ),
            changed_files=list(data.get("changed_files", [])),
            apply_message=data.get("apply_message", ""),
            id=data.get("id", ""),
        )
        p.created_at = data.get("created_at", p.created_at)
        p.applied_at = data.get("applied_at", "")
        p.verified_at = data.get("verified_at", "")
        return p


__all__ = ["PatchRecord", "PatchStatus", "VerificationStatus"]
