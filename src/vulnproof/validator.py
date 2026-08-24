"""Non-destructive HTTP validation executor."""

from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from vulnproof.models import Asset, Evidence, Finding, ValidationResult
from vulnproof.playbooks import ValidationPlaybook
from vulnproof.policy import authorize

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}


def _safe_headers(headers: object) -> dict[str, str]:
    return {
        key: "[REDACTED]" if key.lower() in SENSITIVE_HEADERS else value
        for key, value in headers.items()
    }


class HttpValidator:
    """Execute only bounded GET/HEAD probes described by a validated playbook."""

    def run(
        self,
        playbook: ValidationPlaybook,
        finding: Finding,
        asset: Asset,
        target: str,
        approved: bool = False,
    ) -> ValidationResult:
        authorize(playbook, finding, asset, target, approved)
        started = datetime.now(timezone.utc)
        evidence: list[Evidence] = []
        all_matched = True

        try:
            for step in playbook.steps:
                url = urljoin(target.rstrip("/") + "/", step.path.lstrip("/"))
                request = Request(url, method=step.method)
                try:
                    response = urlopen(request, timeout=step.timeout_seconds)
                except HTTPError as exc:
                    response = exc
                body = response.read(step.max_response_bytes).decode(
                    "utf-8", errors="replace"
                )
                status_matched = response.status == step.expected_status
                body_matched = step.body_contains is None or step.body_contains in body
                matched = status_matched and body_matched
                all_matched = all_matched and matched
                evidence.append(
                    Evidence.capture(
                        kind="http-observation",
                        summary=(
                            f"{step.name}: {'matched' if matched else 'did not match'}"
                        ),
                        data={
                            "method": step.method,
                            "url": url,
                            "status": response.status,
                            "expected_status": step.expected_status,
                            "body_contains_matched": body_matched,
                            "response_headers": _safe_headers(response.headers),
                            "body_preview": body,
                            "truncated": len(body.encode()) >= step.max_response_bytes,
                        },
                    )
                )
        except (URLError, TimeoutError, OSError) as exc:
            return ValidationResult(
                playbook_id=playbook.id,
                vulnerability_id=finding.vulnerability_id,
                asset_name=asset.name,
                target=target,
                status="error",
                message=f"validation request failed: {type(exc).__name__}",
                started_at=started,
                completed_at=datetime.now(timezone.utc),
                evidence=evidence,
            )

        status = "confirmed" if all_matched else "not_confirmed"
        return ValidationResult(
            playbook_id=playbook.id,
            vulnerability_id=finding.vulnerability_id,
            asset_name=asset.name,
            target=target,
            status=status,
            message=(
                "all validation conditions matched"
                if all_matched
                else "one or more validation conditions did not match"
            ),
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            evidence=evidence,
        )
