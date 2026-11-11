"""Bounded, provider-aware tool inputs. No caller-supplied API methods or URLs."""

import re
from typing import Literal

from pydantic import Field, model_validator

from sec_auditor.models import StrictModel

ProviderName = Literal["gcp", "alicloud"]


class ResourceQuery(StrictModel):
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


class KubernetesQuery(StrictModel):
    provider: ProviderName = "gcp"
    cluster: str = Field(max_length=256)
    kind: str = Field(default="Pod", max_length=64)
    namespace: str | None = Field(default=None, max_length=63)
    page_size: int = Field(default=100, ge=1, le=500)
    cursor: str | None = Field(default=None, max_length=24000)


class LogQuery(StrictModel):
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


class AssessmentRequest(StrictModel):
    scope: str | None = Field(default=None, max_length=96)
    projects: list[str] = Field(default_factory=list, max_length=1000)
    accounts: list[str] = Field(default_factory=list, max_length=100)
    clusters: list[str] = Field(default_factory=list, max_length=1000)
    queries: list[ResourceQuery] = Field(default_factory=list, max_length=100)
    resource_kinds: list[str] | None = Field(default=None, max_length=200)
    kubernetes_kinds: list[str] | None = Field(default=None, max_length=50)
    locations: list[str] = Field(default_factory=list, max_length=50)
    check_ids: list[str] | None = Field(default=None, max_length=500)
    include_kubernetes: bool = True
    include_passes: bool = False

    @model_validator(mode="after")
    def targets(self) -> "AssessmentRequest":
        if (
            not self.scope
            and not self.projects
            and not self.accounts
            and not self.clusters
            and not self.queries
        ):
            raise ValueError("Provide a scope, explicit projects, accounts, clusters, or queries")
        if self.clusters and not self.include_kubernetes:
            raise ValueError("Explicit clusters require include_kubernetes=true")
        if self.resource_kinds is not None:
            if any(kind.startswith("gcp.") for kind in self.resource_kinds) and not (
                self.scope or self.projects
            ):
                raise ValueError(
                    "GCP resource_kinds need a discovery scope or projects; use queries for explicit targets"
                )
            if (
                any(kind.startswith("alicloud.") for kind in self.resource_kinds)
                and not self.accounts
            ):
                raise ValueError(
                    "Alibaba resource_kinds need accounts; use queries for explicit targets"
                )
        if any(query.cursor for query in self.queries):
            raise ValueError("Assessment queries start at the first page; do not supply cursors")
        if any(not re.fullmatch(r"[0-9]{8,32}", value) for value in self.accounts):
            raise ValueError("Alibaba accounts must be numeric account IDs")
        if any(
            len(value) > 256
            for group in (self.projects, self.clusters, self.locations)
            for value in group
        ):
            raise ValueError("Target identifier is too long")
        return self
