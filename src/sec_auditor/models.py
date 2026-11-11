"""Provider-neutral evidence and check contracts."""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResourceRecord(StrictModel):
    provider: str = "gcp"
    kind: str
    name: str
    project: str | None = None
    account_id: str | None = None
    location: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=utcnow)
    freshness: Literal["live", "inventory", "cached"] = "live"
    source: str = ""


class CollectionError(StrictModel):
    target: str
    code: str
    message: str
    retryable: bool = False


class CollectionResult(StrictModel):
    items: list[ResourceRecord] = Field(default_factory=list)
    next_page_token: str | None = None
    warnings: list[str] = Field(default_factory=list)
    errors: list[CollectionError] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CheckDefinition(StrictModel):
    id: str
    title: str
    description: str
    resource_kind: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    remediation: str = ""


class CheckResult(StrictModel):
    check_id: str
    resource: str
    status: Literal["pass", "fail", "unknown", "not_applicable"]
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    title: str
    summary: str
    evidence_paths: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
