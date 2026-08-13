from datetime import datetime, timezone

from vulnproof.models import Asset, Finding, ScanReport


def test_scan_report_composes_asset_and_finding() -> None:
    asset = Asset(
        name="payment-api",
        environment="lab",
        criticality="critical",
        internet_exposed=True,
    )
    finding = Finding(
        vulnerability_id="CVE-2099-0001",
        package_name="example-package",
        severity="HIGH",
        cvss_score=8.1,
        asset_name=asset.name,
        source="fixture",
    )

    report = ScanReport(
        asset=asset,
        findings=[finding],
        generated_at=datetime.now(timezone.utc),
    )

    assert report.asset.name == "payment-api"
    assert report.findings[0].vulnerability_id == "CVE-2099-0001"
