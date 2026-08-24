import pytest

from vulnproof.models import Asset, Finding
from vulnproof.playbooks import HttpStep, ValidationPlaybook
from vulnproof.policy import PolicyViolation, authorize


def objects():
    asset = Asset(
        name="demo",
        environment="lab",
        validation_enabled=True,
        allowed_hosts=["127.0.0.1"],
    )
    finding = Finding(
        vulnerability_id="VP-LAB-0001",
        package_name="demo",
        asset_name="demo",
        source="fixture",
    )
    playbook = ValidationPlaybook(
        id="vp-lab-0001",
        description="test",
        vulnerability_ids=["VP-LAB-0001"],
        steps=[HttpStep(name="probe", path="/", expected_status=200)],
    )
    return playbook, finding, asset


def test_policy_requires_explicit_approval() -> None:
    with pytest.raises(PolicyViolation, match="approve"):
        authorize(*objects(), "http://127.0.0.1:8080", approved=False)


def test_policy_rejects_host_outside_allowlist() -> None:
    with pytest.raises(PolicyViolation, match="allowlist"):
        authorize(*objects(), "https://example.com", approved=True)


def test_policy_accepts_declared_lab_target() -> None:
    authorize(*objects(), "http://127.0.0.1:8080", approved=True)
