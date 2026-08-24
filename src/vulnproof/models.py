"""Core domain models.

These models intentionally do not know how a scanner, cloud provider, or
reporter works. Adapters translate external data into these models.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
AssetCriticality = Literal["low", "medium", "high", "critical"]
FindingStatus = Literal[
    "candidate", "reachable", "confirmed", "not_confirmed", "remediated"
]
ValidationStatus = Literal["confirmed", "not_confirmed", "error"]


class Asset(BaseModel):
    """A business or technical asset being assessed."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    environment: str = "unknown"
    criticality: AssetCriticality = "medium"
    internet_exposed: bool = False
    owner: str | None = None
    data_classification: str | None = None
    validation_enabled: bool = False
    allowed_hosts: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A normalized vulnerability finding from any scanner."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(min_length=1)
    package_name: str = Field(min_length=1)
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: Severity = "UNKNOWN"
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    asset_name: str
    source: str
    priority_score: float | None = Field(default=None, ge=0, le=100)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    in_kev: bool = False
    status: FindingStatus = "candidate"
    score_reasons: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Immutable result boundary returned by a scan pipeline."""

    model_config = ConfigDict(extra="forbid")

    tool_version: str | None = None
    asset: Asset
    findings: list[Finding] = Field(default_factory=list)
    generated_at: datetime


class Evidence(BaseModel):
    """Tamper-evident, size-bounded observation produced by a validator."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    summary: str
    observed_at: datetime
    data: dict[str, object] = Field(default_factory=dict)
    sha256: str

    @classmethod
    def capture(cls, kind: str, summary: str, data: dict[str, object]) -> "Evidence":
        canonical = json.dumps(data, ensure_ascii=False, sort_keys=True).encode()
        return cls(
            kind=kind,
            summary=summary,
            observed_at=datetime.now(timezone.utc),
            data=data,
            sha256=hashlib.sha256(canonical).hexdigest(),
        )


class ValidationResult(BaseModel):
    """Result of executing one validation playbook for one finding."""

    model_config = ConfigDict(extra="forbid")

    playbook_id: str
    vulnerability_id: str
    asset_name: str
    target: str
    status: ValidationStatus
    message: str
    started_at: datetime
    completed_at: datetime
    evidence: list[Evidence] = Field(default_factory=list)


class RetestReport(BaseModel):
    """Before/after evidence proving whether a remediation changed exposure."""

    model_config = ConfigDict(extra="forbid")

    finding: Finding
    before: ValidationResult
    after: ValidationResult
    remediation_verified: bool
    generated_at: datetime
