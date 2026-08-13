"""Core domain models.

These models intentionally do not know how a scanner, cloud provider, or
reporter works. Adapters translate external data into these models.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
AssetCriticality = Literal["low", "medium", "high", "critical"]


class Asset(BaseModel):
    """A business or technical asset being assessed."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    environment: str = "unknown"
    criticality: AssetCriticality = "medium"
    internet_exposed: bool = False
    owner: str | None = None
    data_classification: str | None = None


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


class ScanReport(BaseModel):
    """Immutable result boundary returned by a scan pipeline."""

    model_config = ConfigDict(extra="forbid")

    tool_version: str | None = None
    asset: Asset
    findings: list[Finding] = Field(default_factory=list)
    generated_at: datetime
