"""VulnProof command-line interface."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
import yaml

from vulnproof import __version__
from vulnproof.ingestors.trivy import load_trivy
from vulnproof.models import Asset, RetestReport, ScanReport
from vulnproof.playbooks import load_playbook
from vulnproof.reporting import write_json, write_markdown
from vulnproof.scoring import ContextRiskScorer
from vulnproof.validator import HttpValidator

app = typer.Typer(
    name="vulnproof",
    help="Evidence-driven security validation for authorized lab environments.",
    no_args_is_help=True,
)


def _asset(path: Path) -> Asset:
    return Asset.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _scan_report(path: Path) -> ScanReport:
    return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))


def _finding(report: ScanReport, vulnerability_id: str):
    for finding in report.findings:
        if finding.vulnerability_id == vulnerability_id:
            return finding
    raise typer.BadParameter(f"finding not found: {vulnerability_id}")


@app.command()
def version() -> None:
    """Print the installed VulnProof version."""

    typer.echo(__version__)


@app.command()
def ingest(
    trivy_json: Annotated[Path, typer.Argument(exists=True, readable=True)],
    asset_file: Annotated[Path, typer.Option("--asset", exists=True, readable=True)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("reports/scan.json"),
) -> None:
    """Normalize a Trivy JSON report and add asset-context priority scores."""

    asset = _asset(asset_file)
    report = load_trivy(trivy_json, asset)
    scorer = ContextRiskScorer()
    report = report.model_copy(
        update={"findings": [scorer.score(item, asset) for item in report.findings]}
    )
    write_json(report, output)
    write_markdown(report, output.with_suffix(".md"))
    typer.echo(f"normalized {len(report.findings)} finding(s) -> {output}")


@app.command()
def validate(
    scan_report: Annotated[Path, typer.Argument(exists=True, readable=True)],
    vulnerability_id: Annotated[str, typer.Option("--finding")],
    playbook_file: Annotated[
        Path, typer.Option("--playbook", exists=True, readable=True)
    ],
    asset_file: Annotated[Path, typer.Option("--asset", exists=True, readable=True)],
    target: Annotated[str, typer.Option("--target")],
    approve: Annotated[bool, typer.Option("--approve")] = False,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(
        "reports/validation.json"
    ),
) -> None:
    """Run an approved, non-destructive playbook and capture evidence."""

    finding = _finding(_scan_report(scan_report), vulnerability_id)
    result = HttpValidator().run(
        load_playbook(playbook_file),
        finding,
        _asset(asset_file),
        target,
        approved=approve,
    )
    write_json(result, output)
    write_markdown(result, output.with_suffix(".md"))
    typer.echo(f"validation status: {result.status} -> {output}")


@app.command()
def retest(
    scan_report: Annotated[Path, typer.Argument(exists=True, readable=True)],
    vulnerability_id: Annotated[str, typer.Option("--finding")],
    playbook_file: Annotated[
        Path, typer.Option("--playbook", exists=True, readable=True)
    ],
    asset_file: Annotated[Path, typer.Option("--asset", exists=True, readable=True)],
    before_target: Annotated[str, typer.Option("--before-target")],
    after_target: Annotated[str, typer.Option("--after-target")],
    approve: Annotated[bool, typer.Option("--approve")] = False,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(
        "reports/retest.json"
    ),
) -> None:
    """Compare vulnerable and remediated targets using the same playbook."""

    finding = _finding(_scan_report(scan_report), vulnerability_id)
    playbook = load_playbook(playbook_file)
    asset = _asset(asset_file)
    validator = HttpValidator()
    before = validator.run(playbook, finding, asset, before_target, approved=approve)
    after = validator.run(playbook, finding, asset, after_target, approved=approve)
    report = RetestReport(
        finding=finding,
        before=before,
        after=after,
        remediation_verified=(
            before.status == "confirmed" and after.status == "not_confirmed"
        ),
        generated_at=datetime.now(timezone.utc),
    )
    write_json(report, output)
    write_markdown(report, output.with_suffix(".md"))
    typer.echo(
        f"remediation verified: {str(report.remediation_verified).lower()} -> {output}"
    )
