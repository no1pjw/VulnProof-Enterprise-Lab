"""Reusable orchestration independent of CLI and vendor adapters."""

from datetime import datetime, timezone

from vulnproof.models import Asset, Finding, RetestReport
from vulnproof.playbooks import ValidationPlaybook
from vulnproof.validator import HttpValidator


class RetestPipeline:
    def __init__(self, validator: HttpValidator | None = None) -> None:
        self.validator = validator or HttpValidator()

    def run(
        self,
        playbook: ValidationPlaybook,
        finding: Finding,
        asset: Asset,
        before_target: str,
        after_target: str,
        approved: bool,
    ) -> RetestReport:
        before = self.validator.run(
            playbook, finding, asset, before_target, approved=approved
        )
        after = self.validator.run(
            playbook, finding, asset, after_target, approved=approved
        )
        return RetestReport(
            finding=finding,
            before=before,
            after=after,
            remediation_verified=(
                before.status == "confirmed" and after.status == "not_confirmed"
            ),
            generated_at=datetime.now(timezone.utc),
        )
