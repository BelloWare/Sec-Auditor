"""Explicit deployment policy. No scope or remote authentication is inferred."""

import re
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sec_auditor.models import StrictModel


class KubernetesConnection(StrictModel):
    """Operator-registered ACK endpoint; callers cannot choose URLs or credentials."""

    server: str = Field(max_length=512)
    ca_file: Path
    token_file: Path


class AlicloudLogStore(StrictModel):
    """A specifically approved SLS destination for security telemetry."""

    account_id: str = Field(pattern=r"^[0-9]{8,32}$")
    region: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    project: str = Field(pattern=r"^[a-z][a-z0-9-]{1,61}[a-z0-9]$")
    logstore: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")
    category: Literal["audit", "vpc_flows", "firewall", "kubernetes"] = "vpc_flows"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SEC_AUDITOR_", env_file=None, extra="ignore")

    allowed_organizations: list[str] = Field(default_factory=list)
    allowed_projects: list[str] = Field(default_factory=list)
    allowed_alicloud_accounts: list[str] = Field(default_factory=list)
    allowed_alicloud_regions: list[str] = Field(default_factory=list)
    alicloud_kubernetes_clusters: dict[str, KubernetesConnection] = Field(default_factory=dict)
    alicloud_logstores: dict[str, AlicloudLogStore] = Field(default_factory=dict)
    quota_project: str | None = None
    auth_mode: Literal["jwt", "static"] = "jwt"
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwks_url: str = ""
    jwt_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    allowed_subjects: list[str] = Field(default_factory=list)
    required_scopes: list[str] = Field(default_factory=lambda: ["security:read"])
    static_tokens: dict[str, SecretStr] = Field(default_factory=dict)
    public_url: str = "http://localhost:8000/mcp"
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)
    state_path: Path = Path(".state/sec-auditor.sqlite3")
    max_concurrency: int = Field(default=12, ge=1, le=128)
    per_api_concurrency: int = Field(default=4, ge=1, le=32)
    requests_per_second: float = Field(default=5, gt=0, le=100)
    request_timeout: float = Field(default=30, ge=1, le=120)
    request_retries: int = Field(default=2, ge=0, le=5)
    max_api_response_bytes: int = Field(default=16_000_000, ge=100_000, le=64_000_000)
    max_response_bytes: int = Field(default=500_000, ge=10_000, le=2_000_000)
    max_batch_size: int = Field(default=20, ge=1, le=100)
    max_page_size: int = Field(default=200, ge=1, le=1000)
    max_log_hours: int = Field(default=24, ge=1, le=168)
    max_scan_pages: int = Field(default=20, ge=1, le=1000)
    max_scan_resources: int = Field(default=5000, ge=1, le=100_000)
    max_scan_seconds: int = Field(default=600, ge=10, le=3600)
    max_pending_jobs: int = Field(default=20, ge=1, le=100)
    evidence_ttl_seconds: int = Field(default=3600, ge=60, le=604800)
    retention_seconds: int = Field(default=86400, ge=3600, le=604800)
    scope_cache_seconds: int = Field(default=60, ge=0, le=300)
    kubernetes_endpoint: Literal["auto", "dns", "private", "public"] = "auto"

    @field_validator("allowed_organizations")
    @classmethod
    def organization_ids(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[0-9]{1,30}", item) for item in value):
            raise ValueError("Organization scopes must be numeric organization IDs")
        return sorted(set(value))

    @field_validator("allowed_projects")
    @classmethod
    def project_ids(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20}", x) for x in value):
            raise ValueError("Project scopes must be project IDs or project numbers")
        return sorted(set(value))

    @field_validator("allowed_alicloud_accounts")
    @classmethod
    def account_ids(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[0-9]{8,32}", item) for item in value):
            raise ValueError("Alibaba scopes must be numeric account IDs")
        return sorted(set(value))

    @field_validator("allowed_alicloud_regions")
    @classmethod
    def alicloud_regions(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", item) for item in value):
            raise ValueError("Alibaba regions must be explicit region identifiers")
        return sorted(set(value))

    @field_validator("static_tokens")
    @classmethod
    def token_digests(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        seen: set[str] = set()
        for subject, digest in value.items():
            if not subject or not re.fullmatch(r"[a-fA-F0-9]{64}", digest.get_secret_value()):
                raise ValueError("Static tokens map caller names to SHA-256 hex digests")
            normalized = digest.get_secret_value().lower()
            if normalized in seen:
                raise ValueError("Static token digests must be unique to each caller")
            seen.add(normalized)
        return value

    @model_validator(mode="after")
    def explicit_scope(self) -> "Settings":
        if (
            not self.allowed_organizations
            and not self.allowed_projects
            and not self.allowed_alicloud_accounts
        ):
            raise ValueError(
                "Configure at least one allowed organization, project, or Alibaba account"
            )
        for cluster in self.alicloud_kubernetes_clusters:
            match = re.fullmatch(
                r"accounts/([0-9]{8,32})/regions/([a-z][a-z0-9-]{1,63})/clusters/([a-zA-Z0-9][a-zA-Z0-9_-]{0,127})",
                cluster,
            )
            if (
                not match
                or match[1] not in self.allowed_alicloud_accounts
                or match[2] not in self.allowed_alicloud_regions
            ):
                raise ValueError(
                    "Registered ACK clusters must belong to allowed accounts and regions"
                )
        for name, destination in self.alicloud_logstores.items():
            if (
                not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name)
                or destination.account_id not in self.allowed_alicloud_accounts
                or destination.region not in self.allowed_alicloud_regions
            ):
                raise ValueError(
                    "Registered SLS log stores must belong to allowed accounts and regions"
                )
        if not self.jwt_algorithms or any(
            x not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
            for x in self.jwt_algorithms
        ):
            raise ValueError("Only explicitly configured asymmetric JWT algorithms are supported")
        return self
