"""Fail-closed authorization and scope checks for active validation."""

from urllib.parse import urlparse

from vulnproof.models import Asset, Finding
from vulnproof.playbooks import ValidationPlaybook


class PolicyViolation(ValueError):
    """Raised before any request when validation is outside declared policy."""


def authorize(
    playbook: ValidationPlaybook,
    finding: Finding,
    asset: Asset,
    target: str,
    approved: bool,
) -> None:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PolicyViolation("target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise PolicyViolation("credentials are not allowed in target URLs")
    if playbook.destructive:
        raise PolicyViolation("destructive playbooks are not supported")
    if not asset.validation_enabled:
        raise PolicyViolation("active validation is disabled for this asset")
    if playbook.requires_approval and not approved:
        raise PolicyViolation("explicit --approve is required")
    if asset.environment not in playbook.allowed_environments:
        raise PolicyViolation("asset environment is not allowed by the playbook")
    if parsed.hostname not in asset.allowed_hosts:
        raise PolicyViolation("target host is outside the asset allowlist")
    if finding.vulnerability_id not in playbook.vulnerability_ids:
        raise PolicyViolation("playbook does not declare this vulnerability ID")
