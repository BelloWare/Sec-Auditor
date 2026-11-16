"""Bounded, provider-aware tool inputs. No caller-supplied API methods or URLs."""

import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from sec_auditor.models import StrictModel

ProviderName = Literal["gcp", "alicloud"]


def validate_fields(value: list[str] | None) -> list[str] | None:
    if value is not None and (
        not isinstance(value, list)
        or not 1 <= len(value) <= 30
        or any(
            not isinstance(path, str)
            or len(path) > 160
            or not re.fullmatch(r"[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*", path)
            for path in value
        )
    ):
        raise ValueError(
            "fields must contain 1 to 30 simple dot-separated paths of at most 160 characters"
        )
    return value


class ReadQuery(StrictModel):
    fields: list[str] | None = Field(default=None, min_length=1, max_length=30)

    @field_validator("fields")
    @classmethod
    def selected_fields(cls, value: list[str] | None) -> list[str] | None:
        return validate_fields(value)


class ResourceQuery(ReadQuery):
    provider: ProviderName = "gcp"
    kind: str = Field(max_length=128)
    project: str | None = Field(default=None, max_length=64)
    scope: str | None = Field(default=None, max_length=96)
    account_id: str | None = Field(default=None, pattern=r"^[0-9]{8,32}$")
    location: str | None = Field(default=None, max_length=64)
    operation: Literal["list", "get"] = "list"
    parent: str | None = Field(default=None, max_length=1024)
    resource_id: str | None = Field(default=None, max_length=1024)
    selectors: dict[str, str] = Field(default_factory=dict, max_length=20)
    page_size: int = Field(default=100, ge=1, le=1000)
    cursor: str | None = Field(default=None, max_length=24000)

    @model_validator(mode="after")
    def provider_scope(self) -> "ResourceQuery":
        if not self.kind.startswith(self.provider + "."):
            raise ValueError("Resource kind must match its provider")
        if self.provider == "gcp":
            if bool(self.project) == bool(self.scope) or self.account_id is not None:
                raise ValueError(
                    "GCP queries require exactly one project or scope, and no account_id"
                )
        elif not self.account_id or self.project is not None or self.scope is not None:
            raise ValueError("Alibaba queries require account_id, and no GCP project or scope")
        if any(
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key) or len(value) > 4000
            for key, value in self.selectors.items()
        ):
            raise ValueError("Selectors must be bounded names and values from the query capability")
        return self

    @property
    def target(self) -> str:
        return self.project or self.scope or self.account_id or "query"


class KubernetesQuery(ReadQuery):
    provider: ProviderName = "gcp"
    cluster: str = Field(max_length=256)
    kind: str = Field(default="Pod", max_length=64)
    namespace: str | None = Field(default=None, max_length=63)
    operation: Literal["list", "get"] = "list"
    resource_id: str | None = Field(default=None, min_length=1, max_length=512)
    page_size: int = Field(default=100, ge=1, le=500)
    cursor: str | None = Field(default=None, max_length=24000)

    @model_validator(mode="after")
    def read_operation(self) -> "KubernetesQuery":
        if self.operation == "get" and (not self.resource_id or self.cursor is not None):
            raise ValueError("Kubernetes get requires resource_id and does not accept a cursor")
        if self.operation == "list" and self.resource_id is not None:
            raise ValueError("Use operation=get to read a named Kubernetes resource")
        if self.resource_id is not None and (
            self.resource_id in {".", ".."}
            or any(char in self.resource_id for char in "/\\%?#")
            or any(ord(char) < 32 for char in self.resource_id)
        ):
            raise ValueError("Kubernetes resource_id must be a single object name")
        return self


class LogQuery(ReadQuery):
    provider: ProviderName = "gcp"
    project: str | None = Field(default=None, max_length=64)
    account_id: str | None = Field(default=None, pattern=r"^[0-9]{8,32}$")
    location: str | None = Field(default=None, max_length=64)
    category: Literal[
        "audit", "data_access", "vpc_flows", "firewall", "gke", "kubernetes", "all_metadata"
    ] = "audit"
    logstore: str | None = Field(default=None, max_length=64)
    start_time: str | None = Field(default=None, max_length=64)
    end_time: str | None = Field(default=None, max_length=64)
    filter: str = Field(default="", max_length=4000)
    view: str | None = Field(default=None, max_length=512)
    page_size: int = Field(default=100, ge=1, le=1000)
    cursor: str | None = Field(default=None, max_length=24000)

    @model_validator(mode="after")
    def provider_scope(self) -> "LogQuery":
        if self.provider == "gcp":
            if not self.project or self.account_id is not None or self.logstore or self.location:
                raise ValueError(
                    "GCP logs require project, with no Alibaba account, region, or logstore"
                )
        elif not self.account_id or self.project is not None or self.view:
            raise ValueError("Alibaba logs require account_id, with no GCP project or view")
        return self
