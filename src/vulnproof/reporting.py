"""Machine-readable and reviewer-friendly report writers."""

from pathlib import Path

from pydantic import BaseModel

from vulnproof.models import RetestReport, ScanReport, ValidationResult


def write_json(model: BaseModel, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(model.model_dump_json(indent=2), encoding="utf-8")


def write_markdown(
    report: ScanReport | ValidationResult | RetestReport, destination: Path
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(report, RetestReport):
        text = _retest_markdown(report)
    elif isinstance(report, ValidationResult):
        text = _validation_markdown(report)
    else:
        rows = "\n".join(
            f"| {f.vulnerability_id} | {f.severity} | {f.priority_score} | {f.status} |"
            for f in report.findings
        )
        text = (
            f"# Scan report: {report.asset.name}\n\n"
            "| Finding | Severity | Priority | Status |\n|---|---:|---:|---|\n"
            f"{rows}\n"
        )
    destination.write_text(text, encoding="utf-8")


def _validation_markdown(result: ValidationResult) -> str:
    items = "\n".join(f"- `{item.sha256}` — {item.summary}" for item in result.evidence)
    return (
        f"# Validation: {result.vulnerability_id}\n\n"
        f"- Asset: `{result.asset_name}`\n- Status: **{result.status}**\n"
        f"- Playbook: `{result.playbook_id}`\n- Target: `{result.target}`\n\n"
        f"## Evidence ledger\n\n{items or '- No evidence captured'}\n"
    )


def _retest_markdown(report: RetestReport) -> str:
    verdict = "VERIFIED" if report.remediation_verified else "NOT VERIFIED"
    return (
        f"# Remediation retest: {report.finding.vulnerability_id}\n\n"
        f"- Before: **{report.before.status}**\n"
        f"- After: **{report.after.status}**\n"
        f"- Remediation: **{verdict}**\n\n"
        "Evidence hashes are available in the JSON report.\n"
    )
