"""Application-level orchestration for the initial scan flow."""

from collections.abc import Iterable
from datetime import datetime, timezone

from .models import Asset, ScanReport
from .ports import Enricher, RiskScorer, Scanner


class ScanPipeline:
    """Coordinate adapters without embedding vendor-specific logic."""

    def __init__(
        self,
        scanner: Scanner,
        scorer: RiskScorer,
        enrichers: Iterable[Enricher] = (),
    ) -> None:
        self.scanner = scanner
        self.scorer = scorer
        self.enrichers = tuple(enrichers)

    def run(self, target: str, asset: Asset) -> ScanReport:
        findings = list(self.scanner.scan(target, asset))

        for enricher in self.enrichers:
            findings = list(enricher.enrich(findings))

        findings = [self.scorer.score(finding, asset) for finding in findings]

        return ScanReport(
            tool_version=getattr(self.scanner, "version", None),
            asset=asset,
            findings=findings,
            generated_at=datetime.now(timezone.utc),
        )
