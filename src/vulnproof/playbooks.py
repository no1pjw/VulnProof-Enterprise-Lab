"""Declarative, reviewable validation playbooks."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class HttpStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    method: Literal["GET", "HEAD"] = "GET"
    path: str = Field(pattern=r"^/")
    expected_status: int = Field(ge=100, le=599)
    body_contains: str | None = None
    timeout_seconds: float = Field(default=5, gt=0, le=15)
    max_response_bytes: int = Field(default=4096, ge=0, le=16384)


class ValidationPlaybook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]+$")
    description: str
    vulnerability_ids: list[str] = Field(min_length=1)
    allowed_environments: list[str] = Field(default_factory=lambda: ["lab"])
    destructive: bool = False
    requires_approval: bool = True
    steps: list[HttpStep] = Field(min_length=1)


def load_playbook(path: Path) -> ValidationPlaybook:
    return ValidationPlaybook.model_validate(
        yaml.safe_load(path.read_text(encoding="utf-8"))
    )
