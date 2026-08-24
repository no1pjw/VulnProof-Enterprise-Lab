"""Transparent, deterministic prioritization for normalized findings."""

from vulnproof.models import Asset, Finding

CRITICALITY_WEIGHT = {"low": 0, "medium": 5, "high": 12, "critical": 20}


class ContextRiskScorer:
    """Score technical severity together with small, explainable asset factors."""

    def score(self, finding: Finding, asset: Asset) -> Finding:
        reasons: list[str] = []
        base = (finding.cvss_score or 0) * 6
        reasons.append(f"CVSS contribution: {base:.1f}")
        criticality = CRITICALITY_WEIGHT[asset.criticality]
        reasons.append(f"Asset criticality contribution: {criticality}")
        exposure = 15 if asset.internet_exposed else 0
        if exposure:
            reasons.append("Internet exposure contribution: 15")
        known_exploitation = 20 if finding.in_kev else 0
        if known_exploitation:
            reasons.append("Known-exploited contribution: 20")
        score = min(100.0, base + criticality + exposure + known_exploitation)
        return finding.model_copy(
            update={"priority_score": round(score, 1), "score_reasons": reasons}
        )
