"""Translate Trivy JSON into VulnProof's vendor-neutral model."""

import json
from pathlib import Path

from vulnproof.models import Asset, Finding, ScanReport


def _cvss_score(item: dict[str, object]) -> float | None:
    cvss = item.get("CVSS")
    if not isinstance(cvss, dict):
        return None
    scores = []
    for vendor in cvss.values():
        if isinstance(vendor, dict):
            for key in ("V3Score", "V2Score"):
                value = vendor.get(key)
                if isinstance(value, (int, float)):
                    scores.append(float(value))
                    break
    return max(scores, default=None)


def load_trivy(path: Path, asset: Asset) -> ScanReport:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for result in raw.get("Results", []):
        for item in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    vulnerability_id=item["VulnerabilityID"],
                    package_name=item.get("PkgName", "unknown"),
                    installed_version=item.get("InstalledVersion"),
                    fixed_version=item.get("FixedVersion"),
                    severity=item.get("Severity", "UNKNOWN"),
                    cvss_score=_cvss_score(item),
                    asset_name=asset.name,
                    source="trivy",
                )
            )
    from datetime import datetime, timezone

    return ScanReport(
        tool_version=raw.get("Metadata", {}).get("OS", {}).get("Version"),
        asset=asset,
        findings=findings,
        generated_at=datetime.now(timezone.utc),
    )
