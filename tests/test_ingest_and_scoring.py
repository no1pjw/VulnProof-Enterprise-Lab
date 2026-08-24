from pathlib import Path

from vulnproof.ingestors.trivy import load_trivy  # noqa: E402
from vulnproof.models import Asset  # noqa: E402
from vulnproof.scoring import ContextRiskScorer  # noqa: E402

FIXTURE = Path(__file__).parents[1] / "fixtures" / "trivy-demo.json"


def test_trivy_finding_is_normalized_and_scored() -> None:
    asset = Asset(name="demo", environment="lab", criticality="high")
    report = load_trivy(FIXTURE, asset)
    finding = ContextRiskScorer().score(report.findings[0], asset)

    assert finding.vulnerability_id == "VP-LAB-0001"
    assert finding.source == "trivy"
    assert finding.priority_score == 60.0
    assert finding.score_reasons
