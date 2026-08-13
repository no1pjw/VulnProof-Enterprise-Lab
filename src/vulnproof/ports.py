"""Extension contracts used by the application layer.

Concrete integrations such as Trivy or the FIRST EPSS API belong in adapter
modules. Keeping these contracts small makes each adapter independently
testable and replaceable.
"""

from collections.abc import Sequence
from typing import Protocol

from .models import Asset, Finding, ScanReport


class Scanner(Protocol):
    """Convert a target into normalized findings."""

    name: str

    def scan(self, target: str, asset: Asset) -> Sequence[Finding]:
        ...


class Enricher(Protocol):
    """Add contextual intelligence to normalized findings."""

    name: str

    def enrich(self, findings: Sequence[Finding]) -> Sequence[Finding]:
        ...


class RiskScorer(Protocol):
    """Calculate a bounded priority score for each finding."""

    def score(self, finding: Finding, asset: Asset) -> Finding:
        ...


class Reporter(Protocol):
    """Render a scan report for a human or another tool."""

    name: str

    def write(self, report: ScanReport, destination: str) -> None:
        ...
