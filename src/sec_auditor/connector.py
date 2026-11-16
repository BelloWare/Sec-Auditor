"""Reusable, bounded cloud reads without MCP, jobs, or persistent storage.

Callers embedding this class must authenticate their users before supplying the
actor identity. All reads still enforce configured cloud scope and projection.
"""

import asyncio
import logging
import uuid
from typing import Any

from sec_auditor.config import Settings
from sec_auditor.cursors import CursorCodec, canonical_json, validate_actor
from sec_auditor.logging_reader import LoggingReader, summarize_flows
from sec_auditor.models import CollectionError, CollectionResult, utcnow
from sec_auditor.policy import ScopeDenied, ScopePolicy
from sec_auditor.projection import project_record, safe_text, sanitize
from sec_auditor.providers.capabilities import grouped_capabilities
from sec_auditor.providers.catalog import SAFE_ASSET_TYPES
from sec_auditor.providers.gcp import GCPProvider
from sec_auditor.providers.kubernetes import KubernetesProvider, cluster_project, normalize_kind
from sec_auditor.providers.kubernetes_registered import (
    RegisteredKubernetesProvider,
    cluster_account,
)
from sec_auditor.requests import KubernetesQuery, LogQuery, ResourceQuery, validate_fields
from sec_auditor.transport import CloudAPIError, GoogleRestClient

LOG = logging.getLogger("sec_auditor.audit")


def _error(target: str, exc: Exception) -> CollectionError:
    if isinstance(exc, CloudAPIError):
        return CollectionError(
            target=safe_text(target, 256),
            code=exc.code,
            message=exc.message,
            retryable=exc.retryable,
        )
    if isinstance(exc, ScopeDenied):
        return CollectionError(
            target=safe_text(target, 256),
            code="SCOPE_DENIED",
            message="Target is outside the configured audit scope",
        )
    if isinstance(exc, (ValueError, TypeError)):
        return CollectionError(
            target=safe_text(target, 256), code="INVALID_ARGUMENT", message=safe_text(str(exc), 256)
        )
    if isinstance(exc, TimeoutError):
        return CollectionError(
            target=safe_text(target, 256),
            code="DEADLINE_EXCEEDED",
            message="Collection exceeded its request deadline",
            retryable=True,
        )
    return CollectionError(
        target=safe_text(target, 256),
        code="INTERNAL",
        message="Collection failed; inspect server diagnostics using the request ID",
    )


def _selected_fields(item: dict[str, Any], fields: list[str] | None) -> dict[str, Any]:
    """Narrow only an already projected record, preserving identity and omissions."""
    validate_fields(fields)
    if fields is None:
        return item
    selected = {}
    for path in fields:
        value: Any = item
        for segment in path.split("."):
            if isinstance(value, dict):
                value = value.get(segment)
            elif isinstance(value, list) and segment.isdigit() and int(segment) < len(value):
                value = value[int(segment)]
            else:
                value = None
                break
        selected[path] = value
    metadata = {
        key: item[key]
        for key in (
            "name",
            "kind",
            "provider",
            "project",
            "account_id",
            "location",
            "observed_at",
            "freshness",
            "projection",
            "redacted_path_count",
            "content_is_untrusted",
        )
        if key in item
    }
    paths = item.get("redacted_paths", [])
    metadata["redacted_paths"] = [path[:256] for path in paths[:10]]
    metadata["redacted_paths_truncated"] = len(paths) > 10 or any(
        len(path) > 256 for path in paths[:10]
    )
    return metadata | {"selected": selected}


class CloudConnector:
    def __init__(
        self,
        settings: Settings,
        *,
        client: GoogleRestClient | None = None,
        gcp: GCPProvider | None = None,
        kubernetes: KubernetesProvider | None = None,
        alicloud: Any = None,
        alicloud_client: Any = None,
        registered_kubernetes: RegisteredKubernetesProvider | None = None,
    ):
        self.settings = settings
        self.client = client or GoogleRestClient(settings)
        self.gcp = gcp or GCPProvider(self.client)
        self.kubernetes = kubernetes or KubernetesProvider(
            self.client,
            endpoint_preference=settings.kubernetes_endpoint,
            timeout=settings.request_timeout,
            concurrency=settings.per_api_concurrency,
        )
        self.policy = ScopePolicy(settings, self.client)
        self.logs = LoggingReader(self.client, settings)
        self.alicloud_client = alicloud_client
        self.alicloud = alicloud
        if settings.allowed_alicloud_accounts:
            from sec_auditor.providers.alicloud import AlibabaProvider
            from sec_auditor.providers.alicloud_transport import AlibabaRestClient

            self.alicloud_client = alicloud_client or AlibabaRestClient(settings)
            self.alicloud = alicloud or AlibabaProvider(self.alicloud_client)
        self.registered_kubernetes = registered_kubernetes or RegisteredKubernetesProvider(settings)
        self.cursors = CursorCodec(
            key=bytes.fromhex(settings.cursor_signing_key.get_secret_value())
            if settings.cursor_signing_key is not None
            else None,
            ttl_seconds=settings.cursor_ttl_seconds,
        )
        self._call_slots = asyncio.Semaphore(settings.max_concurrency)
        self._closed = False
        self.ready = False

    async def __aenter__(self) -> "CloudConnector":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close()

    async def start(self) -> None:
        """Mark ready; no worker, database, or credentials are opened here."""
        if self._closed:
            raise RuntimeError("A closed connector cannot be restarted")
        self.ready = True

    async def close(self) -> None:
        if self._closed:
            return
        self.ready = False
        self._closed = True
        clients = [self.kubernetes, self.registered_kubernetes, self.client]
        if self.alicloud_client is not None:
            clients.append(self.alicloud_client)
        # Close every transport even if one reports an error.
        results = await asyncio.gather(
            *(client.aclose() for client in clients), return_exceptions=True
        )
        for result in results:
            if isinstance(result, Exception):
                raise result

    def _actor(self, actor: str) -> None:
        validate_actor(actor)
        if self._closed:
            raise RuntimeError("Connector is closed")

    def capabilities(self) -> dict[str, Any]:
        return {
            "service": "Sec-Auditor",
            "version": "0.3.0",
            "mode": "stateless_connector",
            "providers": (
                ["gcp"]
                if self.settings.allowed_organizations or self.settings.allowed_projects
                else []
            )
            + (["alicloud"] if self.settings.allowed_alicloud_accounts else []),
            "supported_providers": ["gcp", "alicloud"],
            "gcp_resources": grouped_capabilities("gcp", self.gcp.capabilities()),
            "alicloud_resources": grouped_capabilities("alicloud", self.alicloud.capabilities())
            if self.alicloud
            else [],
            "kubernetes_resources": self.kubernetes.capabilities(),
            "configured_scopes": {
                "gcp_organizations": self.settings.allowed_organizations,
                "gcp_projects": self.settings.allowed_projects,
                "alicloud_accounts": self.settings.allowed_alicloud_accounts,
                "alicloud_regions": self.settings.allowed_alicloud_regions,
                "ack_clusters": sorted(self.settings.alicloud_kubernetes_clusters),
                "alicloud_logstores": {
                    name: value.model_dump()
                    for name, value in self.settings.alicloud_logstores.items()
                },
            },
            "query_contract": {
                "gcp": "Set project OR canonical scope. Native get/nested queries declare resource_id, parent and selector requirements in capabilities.",
                "alicloud": "Set provider=alicloud, account_id and location for regional operations. The credential account is independently verified. No Resource Directory membership inheritance is assumed.",
                "alicloud_regions": "Regions restrict API endpoints and service home regions. Cloud Config/Security Center can report resources in other regions of the same verified account; this is not resource-region isolation.",
                "kubernetes": "GKE uses Google identity; ACK uses an operator-registered endpoint and a separately projected read-only Kubernetes token. Both share the same kind allowlist.",
                "bulk": "Mixed-provider queries execute concurrently with separate errors and signed pagination cursors. Keep native query arguments, including page_size, unchanged when resuming. Only local fields selection may change.",
                "fields": "Optional dot paths select from already sanitized records, including numeric list indices. Field selection never bypasses security projection.",
                "oversized_page": "RESPONSE_TOO_LARGE returns no items and no next_cursor. Retry the original input cursor with fewer fields or fewer queries in the batch. Changing page_size requires restarting the query from page one.",
                "cursor_lifetime": "Cursors expire; by default they also stop working when this connector instance restarts. Configure the same cursor_signing_key across workers for continuity. Cursors contain only pagination metadata, not records.",
            },
            "inventory_asset_types": sorted(SAFE_ASSET_TYPES),
            "limits": {
                key: getattr(self.settings, key)
                for key in (
                    "max_batch_size",
                    "max_page_size",
                    "max_response_bytes",
                    "max_log_hours",
                    "cursor_ttl_seconds",
                )
            },
            "boundaries": {
                "cloud_mutations": False,
                "object_downloads": False,
                "secret_payload_reads": False,
                "shell_execution": False,
                "raw_log_payloads": False,
                "unrestricted_kubernetes": False,
            },
            "semantics": "Configuration and existing telemetry. Each request returns one complete upstream page or an explicit error; it performs no assessment. Resource strings remain untrusted data.",
            "persistence": {"records": False, "background_jobs": False, "database": False},
        }

    def _page_size(self, page_size: int) -> None:
        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= self.settings.max_page_size
        ):
            raise ValueError(f"page_size must be between 1 and {self.settings.max_page_size}")

    def _batch_size(self, queries: list) -> None:
        if not isinstance(queries, list) or not 1 <= len(queries) <= self.settings.max_batch_size:
            raise ValueError(f"Provide between 1 and {self.settings.max_batch_size} queries")

    async def _raw_resource(
        self, query: ResourceQuery, token: str | None = None
    ) -> CollectionResult:
        self._page_size(query.page_size)
        if query.provider == "alicloud":
            self._authorize_alicloud(query.account_id, query.location)
            return await self.alicloud.query_resources(
                query.kind,
                query.account_id,
                location=query.location,
                operation=query.operation,
                parent=query.parent,
                resource_id=query.resource_id,
                selectors=query.selectors,
                page_size=query.page_size,
                page_token=token,
            )
        if query.scope:
            target = await self.policy.authorize_scope(query.scope)
        else:
            project = await self.policy.authorize_project(query.project)
            target = project["projectId"]
        if hasattr(self.gcp, "query_resources"):
            return await self.gcp.query_resources(
                query.kind,
                target,
                location=query.location,
                operation=query.operation,
                parent=query.parent,
                resource_id=query.resource_id,
                selectors=query.selectors,
                page_size=query.page_size,
                page_token=token,
            )
        # Compatibility with a simple list-only provider adapter.
        if (
            query.scope
            or query.operation != "list"
            or query.parent
            or query.resource_id
            or query.selectors
        ):
            raise ValueError("This provider adapter does not support detailed resource queries")
        return await self.gcp.list_resources(
            query.kind,
            target,
            location=query.location,
            page_size=query.page_size,
            page_token=token,
        )

    def _authorize_alicloud(self, account_id: str, location: str | None = None) -> None:
        if not self.alicloud or account_id not in self.settings.allowed_alicloud_accounts:
            raise ScopeDenied("Alibaba account is outside the configured scope")
        if location is not None and location not in self.settings.allowed_alicloud_regions:
            raise ScopeDenied("Alibaba region is outside the configured scope")

    def _cluster_provider(self, cluster: str) -> str:
        if cluster.startswith("accounts/"):
            account, region = cluster_account(cluster)
            self._authorize_alicloud(account, region)
            if cluster not in self.settings.alicloud_kubernetes_clusters:
                raise ScopeDenied("ACK cluster is not registered by the operator")
            return "alicloud"
        cluster_project(cluster)
        return "gcp"

    async def _raw_kubernetes(
        self, query: KubernetesQuery, token: str | None = None
    ) -> CollectionResult:
        self._page_size(query.page_size)
        # Reject unsupported types before resolving any cloud identity.
        normalize_kind(query.kind)
        if query.provider == "alicloud":
            if self._cluster_provider(query.cluster) != "alicloud":
                raise ValueError("Cluster identifier does not match its provider")
            provider = self.registered_kubernetes
        else:
            await self.policy.authorize_project(cluster_project(query.cluster))
            provider = self.kubernetes
        if query.operation == "get":
            return await provider.get_object(
                query.cluster, query.kind, query.resource_id, namespace=query.namespace
            )
        return await provider.list_objects(
            query.cluster,
            query.kind,
            namespace=query.namespace,
            page_size=query.page_size,
            page_token=token,
        )

    async def _envelope(
        self,
        actor: str,
        operation: str,
        binding: dict[str, Any],
        result: CollectionResult,
        *,
        budget: int | None = None,
        extra_cursor_state: dict[str, Any] | None = None,
        fields: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        items = [_selected_fields(project_record(item), fields) for item in result.items]
        next_cursor = None
        if result.next_page_token:
            state = dict(extra_cursor_state or {})
            state["token"] = result.next_page_token
            next_cursor = self.cursors.encode_cursor(actor, operation, binding, state)
        envelope = {
            "request_id": uuid.uuid4().hex,
            "observed_at": utcnow().isoformat(),
            "items": items,
            "coverage": {
                "observed_items": len(items),
                "returned_items": len(items),
                "collection_complete": not result.next_page_token and not result.errors,
                "source_errors": len(result.errors),
            },
            "response_truncated": False,
            "next_cursor": next_cursor,
            "errors": [sanitize(error.model_dump(mode="json")) for error in result.errors],
            "warnings": [safe_text(warning) for warning in result.warnings],
            "metadata": sanitize(result.metadata),
            "content_is_untrusted": True,
        }
        if extra:
            envelope.update(sanitize(extra))
        if len(canonical_json(envelope).encode()) <= (budget or self.settings.max_response_bytes):
            return envelope
        # Never publish the native next token when this page did not fit. Doing
        # so would skip observations and cannot be repaired without stored data.
        return {
            "request_id": envelope["request_id"],
            "observed_at": envelope["observed_at"],
            "items": [],
            "coverage": {
                "observed_items": len(items),
                "returned_items": 0,
                "collection_complete": False,
                "source_errors": len(result.errors),
            },
            "response_truncated": True,
            "next_cursor": None,
            "errors": [
                {
                    "target": operation,
                    "code": "RESPONSE_TOO_LARGE",
                    "message": "The complete projected page exceeds the response budget; no rows or continuation were returned. Retry the same input cursor with narrower fields or fewer batch queries. To reduce page_size, restart from page one. If pagination metadata itself is too large, the operator must increase max_response_bytes.",
                    "retryable": False,
                }
            ],
            "warnings": [],
            "metadata": {
                "retry_same_input_cursor": True,
                "pagination_advanced": False,
                **{
                    key: safe_text(str(result.metadata[key]), 64)
                    for key in ("start_time", "end_time")
                    if key in result.metadata
                },
            },
            "content_is_untrusted": True,
        }

    async def _batch(
        self, actor: str, operation: str, queries: list, collect, query_type
    ) -> dict[str, Any]:
        self._actor(actor)
        self._batch_size(queries)
        budget = (self.settings.max_response_bytes - 1024) // len(queries)
        if budget < 2048:
            raise ValueError(
                "Too many queries for the configured response byte budget; use a smaller batch"
            )

        async def one(value):
            binding = {}
            try:
                # model_copy() deliberately skips validation in Pydantic; dump
                # typed inputs and validate again for safe in-process reuse.
                query = query_type.model_validate(
                    value.model_dump() if isinstance(value, query_type) else value
                )
                binding = query.model_dump(exclude={"cursor", "fields"})
                state = (
                    self.cursors.decode_cursor(query.cursor, actor, operation, binding)
                    if query.cursor
                    else {}
                )
                async with self._call_slots:
                    result = await collect(query, state)
                extra_state = {
                    key: result.metadata[key]
                    for key in ("start_time", "end_time")
                    if key in result.metadata
                }
                extra = None
                if (
                    operation == "query_logs"
                    and query.category == "vpc_flows"
                    and query.provider == "gcp"
                ):
                    extra = {"flow_summary": summarize_flows(result.items)}
                return await self._envelope(
                    actor,
                    operation,
                    binding,
                    result,
                    budget=budget,
                    extra_cursor_state=extra_state,
                    fields=query.fields,
                    extra=extra,
                )
            except Exception as exc:
                return await self._envelope(
                    actor,
                    operation,
                    binding,
                    CollectionResult(
                        errors=[
                            _error(
                                str(
                                    binding.get("project")
                                    or binding.get("scope")
                                    or binding.get("account_id")
                                    or binding.get("cluster")
                                    or "query"
                                ),
                                exc,
                            )
                        ]
                    ),
                    budget=budget,
                )

        results = await asyncio.gather(*(one(query) for query in queries))
        LOG.info(
            "tool=%s caller_hash=%s targets=%d errors=%d",
            operation,
            self._actor_hash(actor),
            len(queries),
            sum(bool(result["errors"]) for result in results),
        )
        return {
            "results": results,
            "targets_requested": len(queries),
            "targets_with_errors": sum(bool(result["errors"]) for result in results),
        }

    @staticmethod
    def _actor_hash(actor: str) -> str:
        import hashlib

        return hashlib.sha256(actor.encode()).hexdigest()[:16]

    async def collect_resources(self, actor: str, queries: list[ResourceQuery]) -> dict[str, Any]:
        return await self._batch(
            actor,
            "collect_resources",
            queries,
            lambda query, state: self._raw_resource(query, state.get("token")),
            ResourceQuery,
        )

    async def inspect_kubernetes(
        self, actor: str, queries: list[KubernetesQuery]
    ) -> dict[str, Any]:
        return await self._batch(
            actor,
            "inspect_kubernetes",
            queries,
            lambda query, state: self._raw_kubernetes(query, state.get("token")),
            KubernetesQuery,
        )

    async def query_logs(self, actor: str, queries: list[LogQuery]) -> dict[str, Any]:
        async def collect(query: LogQuery, state: dict[str, Any]) -> CollectionResult:
            self._page_size(query.page_size)
            if query.provider == "alicloud":
                from sec_auditor.alicloud_logs import read_logs

                self._authorize_alicloud(query.account_id, query.location)
                return await read_logs(
                    self.settings, self.alicloud, self.alicloud_client, query, state
                )
            project = await self.policy.authorize_project(query.project)
            return await self.logs.query(
                project["projectId"],
                category="gke" if query.category == "kubernetes" else query.category,
                start_time=state.get("start_time", query.start_time),
                end_time=state.get("end_time", query.end_time),
                filter=query.filter,
                page_size=query.page_size,
                page_token=state.get("token"),
                view=query.view,
            )

        return await self._batch(actor, "query_logs", queries, collect, LogQuery)

    async def inventory(
        self,
        actor: str,
        scope: str,
        *,
        mode: str = "search",
        query: str = "",
        asset_types: list[str] | None = None,
        page_size: int = 100,
        cursor: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        self._actor(actor)
        validate_fields(fields)
        self._page_size(page_size)
        binding = {
            "scope": scope,
            "mode": mode,
            "query": query,
            "asset_types": asset_types,
            "page_size": page_size,
        }
        state = self.cursors.decode_cursor(cursor, actor, "inventory", binding) if cursor else {}
        async with self._call_slots:
            authorized_scope = await self.policy.authorize_scope(scope)
            if mode == "search":
                result = await self.gcp.search_assets(
                    authorized_scope,
                    query,
                    asset_types,
                    page_size=page_size,
                    page_token=state.get("token"),
                )
            elif mode == "configurations":
                if query:
                    raise ValueError(
                        "Configuration inventory does not support a query; select asset_types or use search mode"
                    )
                result = await self.gcp.list_assets(
                    authorized_scope,
                    asset_types,
                    page_size=page_size,
                    page_token=state.get("token"),
                )
            elif mode == "iam":
                result = await self.gcp.search_iam_policies(
                    authorized_scope,
                    query,
                    asset_types,
                    page_size=page_size,
                    page_token=state.get("token"),
                )
            else:
                raise ValueError("Inventory mode must be search, configurations, or iam")
            return await self._envelope(actor, "inventory", binding, result, fields=fields)

    async def iam_context(
        self,
        actor: str,
        scope: str,
        *,
        include_ancestors: bool = False,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        self._actor(actor)
        validate_fields(fields)
        if not isinstance(include_ancestors, bool):
            raise ValueError("include_ancestors must be a boolean")
        async with self._call_slots:
            authorized = await self.policy.authorize_scope(scope)
            combined = CollectionResult(
                metadata={
                    "policy_semantics": "direct_allow_policies",
                    "effective_access_evaluated": False,
                }
            )
            seen: set[str] = set()
            for _ in range(32):
                if authorized in seen:
                    combined.errors.append(
                        CollectionError(
                            target=authorized,
                            code="INVALID_HIERARCHY",
                            message="Hierarchy cycle detected",
                        )
                    )
                    break
                seen.add(authorized)
                result = await self.gcp.get_iam_policy(authorized)
                combined.items.extend(result.items)
                combined.errors.extend(result.errors)
                if not include_ancestors or authorized.startswith("organizations/"):
                    break
                try:
                    resource = await self.client.get(
                        f"https://cloudresourcemanager.googleapis.com/v3/{authorized}"
                    )
                    parent = resource.get("parent")
                    if not parent:
                        break
                    authorized = await self.policy.authorize_scope(parent)
                except Exception as exc:
                    combined.errors.append(_error("ancestor", exc))
                    break
            else:
                combined.errors.append(
                    CollectionError(
                        target=scope,
                        code="HIERARCHY_LIMIT",
                        message="Hierarchy depth limit reached",
                    )
                )
            combined.warnings.append(
                "These are observed allow policies. IAM conditions, deny policies, principal access boundaries and service-specific rules are not evaluated as effective access."
            )
            return await self._envelope(
                actor,
                "iam_context",
                {"scope": scope, "include_ancestors": include_ancestors},
                combined,
                fields=fields,
            )
