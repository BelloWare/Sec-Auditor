"""The security service; protocol-independent so collectors can be reused."""

import asyncio
import contextlib
import logging
import re
import time
import uuid
from collections import Counter
from typing import Any

from sec_auditor.checks import evaluate, list_checks
from sec_auditor.config import Settings
from sec_auditor.logging_reader import LoggingReader, summarize_flows
from sec_auditor.models import CollectionError, CollectionResult, utcnow
from sec_auditor.policy import ScopeDenied, ScopePolicy, validate_project
from sec_auditor.projection import project_record, safe_text, sanitize
from sec_auditor.providers.capabilities import grouped_capabilities
from sec_auditor.providers.catalog import RESOURCE_SPECS, SAFE_ASSET_TYPES
from sec_auditor.providers.gcp import GCPProvider
from sec_auditor.providers.kubernetes import KubernetesProvider, cluster_project, normalize_kind
from sec_auditor.providers.kubernetes_registered import (
    RegisteredKubernetesProvider,
    cluster_account,
)
from sec_auditor.requests import AssessmentRequest, KubernetesQuery, LogQuery, ResourceQuery
from sec_auditor.state import StateStore, canonical_json
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
    if fields is None:
        return item
    if not 1 <= len(fields) <= 30 or any(
        not re.fullmatch(r"[a-zA-Z0-9_.-]{1,160}", path) for path in fields
    ):
        raise ValueError("Evidence fields must be simple dot-separated paths")
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
    return {"name": item.get("name"), "kind": item.get("kind"), "selected": selected}


class SecurityService:
    def __init__(
        self,
        settings: Settings,
        *,
        client: GoogleRestClient | None = None,
        gcp: GCPProvider | None = None,
        kubernetes: KubernetesProvider | None = None,
        store: StateStore | None = None,
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
        self.store = store or StateStore(
            settings.state_path,
            evidence_ttl=settings.evidence_ttl_seconds,
            retention=settings.retention_seconds,
            max_pending=settings.max_pending_jobs,
        )
        self._worker: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._call_slots = asyncio.Semaphore(settings.max_concurrency)
        self.ready = False

    async def start(self) -> None:
        self._stopping.clear()
        self._worker = asyncio.create_task(self._work_loop(), name="assessment-worker")
        self.ready = True

    async def close(self) -> None:
        self.ready = False
        self._stopping.set()
        if self._worker:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
        await self.kubernetes.aclose()
        await self.registered_kubernetes.aclose()
        await self.client.aclose()
        if self.alicloud_client is not None:
            await self.alicloud_client.aclose()

    def capabilities(self) -> dict[str, Any]:
        return {
            "service": "Sec-Auditor",
            "version": "0.2.0",
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
                "bulk": "Mixed-provider queries execute concurrently with separate errors and opaque pagination cursors. Keep identical query arguments when resuming.",
            },
            "inventory_asset_types": sorted(SAFE_ASSET_TYPES),
            "checks": {"count": len(list_checks()), "discovery_tool": "list_security_checks"},
            "limits": {
                key: getattr(self.settings, key)
                for key in (
                    "max_batch_size",
                    "max_page_size",
                    "max_response_bytes",
                    "max_log_hours",
                    "max_scan_pages",
                    "max_scan_resources",
                    "max_scan_seconds",
                    "evidence_ttl_seconds",
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
            "semantics": "Configuration and existing telemetry. Unknown checks and incomplete collections are explicit. Resource strings remain untrusted data.",
        }

    def _page_size(self, page_size: int) -> None:
        if not 1 <= page_size <= self.settings.max_page_size:
            raise ValueError(f"page_size must be between 1 and {self.settings.max_page_size}")

    def _batch_size(self, queries: list) -> None:
        if not 1 <= len(queries) <= self.settings.max_batch_size:
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
        if query.provider == "alicloud":
            if self._cluster_provider(query.cluster) != "alicloud":
                raise ValueError("Cluster identifier does not match its provider")
            return await self.registered_kubernetes.list_objects(
                query.cluster,
                query.kind,
                namespace=query.namespace,
                page_size=query.page_size,
                page_token=token,
            )
        await self.policy.authorize_project(cluster_project(query.cluster))
        return await self.kubernetes.list_objects(
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
        projected_items: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        items = (
            projected_items
            if projected_items is not None
            else [project_record(item) for item in result.items]
        )
        evidence_id = (
            await asyncio.to_thread(self.store.put_evidence, actor, items) if items else None
        )
        max_bytes = max(1000, (budget or self.settings.max_response_bytes) - 7000)
        inline = []
        size = 0
        for item in items:
            item_size = len(canonical_json(item).encode())
            if size + item_size > max_bytes:
                break
            inline.append(item)
            size += item_size
        next_cursor = None
        if result.next_page_token:
            state = dict(extra_cursor_state or {})
            state["token"] = result.next_page_token
            next_cursor = self.store.encode_cursor(actor, operation, binding, state)
        evidence_cursor = None
        if len(inline) < len(items) and evidence_id:
            evidence_cursor = self.store.encode_cursor(
                actor, "evidence", {"id": evidence_id, "fields": None}, {"offset": len(inline)}
            )
        return {
            "request_id": uuid.uuid4().hex,
            "observed_at": utcnow().isoformat(),
            "items": inline,
            "coverage": {
                "observed_items": len(items),
                "returned_items": len(inline),
                "collection_complete": not result.next_page_token and not result.errors,
                "source_errors": len(result.errors),
            },
            "response_truncated": len(inline) < len(items),
            "next_cursor": next_cursor,
            "evidence_id": evidence_id,
            "next_evidence_cursor": evidence_cursor,
            "evidence_expires_in_seconds": self.settings.evidence_ttl_seconds
            if evidence_id
            else None,
            "errors": [sanitize(error.model_dump(mode="json")) for error in result.errors],
            "warnings": [safe_text(warning) for warning in result.warnings],
            "metadata": sanitize(result.metadata),
            "content_is_untrusted": True,
        }

    async def _batch(self, actor: str, operation: str, queries: list, collect) -> dict[str, Any]:
        self._batch_size(queries)
        budget = self.settings.max_response_bytes // len(queries)

        async def one(query):
            binding = query.model_dump(exclude={"cursor"})
            try:
                state = (
                    self.store.decode_cursor(query.cursor, actor, operation, binding)
                    if query.cursor
                    else {}
                )
                async with self._call_slots:
                    result = await collect(query, state)
                extra = {
                    key: result.metadata[key]
                    for key in ("start_time", "end_time")
                    if key in result.metadata
                }
                envelope = await self._envelope(
                    actor, operation, binding, result, budget=budget, extra_cursor_state=extra
                )
                if (
                    operation == "query_logs"
                    and query.category == "vpc_flows"
                    and query.provider == "gcp"
                ):
                    envelope["flow_summary"] = summarize_flows(result.items)
                return envelope
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
        )

    async def inspect_kubernetes(
        self, actor: str, queries: list[KubernetesQuery]
    ) -> dict[str, Any]:
        return await self._batch(
            actor,
            "inspect_kubernetes",
            queries,
            lambda query, state: self._raw_kubernetes(query, state.get("token")),
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

        return await self._batch(actor, "query_logs", queries, collect)

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
    ) -> dict[str, Any]:
        self._page_size(page_size)
        binding = {
            "scope": scope,
            "mode": mode,
            "query": query,
            "asset_types": asset_types,
            "page_size": page_size,
        }
        authorized_scope = await self.policy.authorize_scope(scope)
        state = self.store.decode_cursor(cursor, actor, "inventory", binding) if cursor else {}
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
                authorized_scope, asset_types, page_size=page_size, page_token=state.get("token")
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
        return await self._envelope(actor, "inventory", binding, result)

    async def iam_context(
        self, actor: str, scope: str, *, include_ancestors: bool = False
    ) -> dict[str, Any]:
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
                    target=scope, code="HIERARCHY_LIMIT", message="Hierarchy depth limit reached"
                )
            )
        combined.warnings.append(
            "These are observed allow policies. IAM conditions, deny policies, principal access boundaries and service-specific rules are not evaluated as effective access."
        )
        return await self._envelope(
            actor, "iam_context", {"scope": scope, "include_ancestors": include_ancestors}, combined
        )

    async def evidence(
        self,
        actor: str,
        identifier: str,
        *,
        page_size: int = 100,
        cursor: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        self._page_size(page_size)
        binding = {"id": identifier, "fields": fields}
        state = self.store.decode_cursor(cursor, actor, "evidence", binding) if cursor else {}
        offset = state.get("offset", 0)
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("Invalid evidence offset")
        items = await asyncio.to_thread(self.store.get_evidence, actor, identifier)
        output = []
        size = 0
        index = offset
        for item in items[offset : offset + page_size]:
            selected = _selected_fields(item, fields)
            item_size = len(canonical_json(selected).encode())
            if size + item_size > self.settings.max_response_bytes - 2000:
                if not output:
                    return {
                        "items": [],
                        "evidence_id": identifier,
                        "oversized_item": index,
                        "error": "This item exceeds the response limit; request selected fields using dot-separated paths.",
                        "next_cursor": cursor,
                        "response_truncated": True,
                    }
                break
            output.append(selected)
            size += item_size
            index += 1
        next_cursor = (
            self.store.encode_cursor(actor, "evidence", binding, {"offset": index})
            if index < len(items)
            else None
        )
        return {
            "items": output,
            "evidence_id": identifier,
            "total_items": len(items),
            "offset": offset,
            "next_cursor": next_cursor,
            "response_truncated": next_cursor is not None,
            "content_is_untrusted": True,
        }

    async def run_checks(
        self,
        actor: str,
        queries: list[ResourceQuery],
        kubernetes_queries: list[KubernetesQuery],
        check_ids: list[str] | None,
        include_passes: bool,
    ) -> dict[str, Any]:
        self._batch_size(queries + kubernetes_queries)
        evaluate([], check_ids)  # Validate IDs even when collection returns zero resources.
        results = []
        budget = self.settings.max_response_bytes // (len(queries) + len(kubernetes_queries))

        async def one(query, kind):
            binding = {
                "query": query.model_dump(exclude={"cursor"}),
                "check_ids": check_ids,
                "include_passes": include_passes,
            }
            try:
                state = (
                    self.store.decode_cursor(query.cursor, actor, "run_checks", binding)
                    if query.cursor
                    else {}
                )
                async with self._call_slots:
                    collected = await (
                        self._raw_resource(query, state.get("token"))
                        if kind == "gcp"
                        else self._raw_kubernetes(query, state.get("token"))
                    )
                evidence_id = (
                    await asyncio.to_thread(
                        self.store.put_evidence,
                        actor,
                        [project_record(record) for record in collected.items],
                    )
                    if collected.items
                    else None
                )
                checked = evaluate(collected.items, check_ids)
                counts = dict(Counter(result.status for result in checked))
                selected = [
                    sanitize(result.model_dump(mode="json")) | {"evidence_id": evidence_id}
                    for result in checked
                    if include_passes or result.status != "pass"
                ]
                envelope = await self._envelope(
                    actor, "run_checks", binding, collected, budget=budget, projected_items=selected
                )
                envelope["evaluation"] = {
                    "resources_examined": len(collected.items),
                    "checks_evaluated": len(checked),
                    "status_counts": counts,
                    "passed_results_omitted": not include_passes,
                    "resource_evidence_id": evidence_id,
                }
                if not checked:
                    envelope["warnings"].append(
                        "No applicable checks were evaluated on this page; this is not a passing assessment."
                    )
                return envelope
            except Exception as exc:
                return await self._envelope(
                    actor,
                    "run_checks",
                    binding,
                    CollectionResult(errors=[_error("check_collection", exc)]),
                    budget=budget,
                )

        results.extend(
            await asyncio.gather(
                *(one(query, "gcp") for query in queries),
                *(one(query, "k8s") for query in kubernetes_queries),
            )
        )
        return {
            "results": results,
            "targets_requested": len(results),
            "targets_with_errors": sum(bool(item["errors"]) for item in results),
        }

    async def start_assessment(self, actor: str, request: AssessmentRequest) -> dict[str, Any]:
        evaluate([], request.check_ids)
        if request.scope:
            await self.policy.authorize_scope(request.scope)
        for project in request.projects:
            validate_project(project)
        for cluster in request.clusters:
            self._cluster_provider(cluster)
        for account in request.accounts:
            self._authorize_alicloud(account)
        supported = set(RESOURCE_SPECS) | {item["kind"] for item in self.gcp.capabilities()}
        if self.alicloud:
            supported.update(item["kind"] for item in self.alicloud.capabilities())
        if request.resource_kinds is not None and any(
            kind not in supported for kind in request.resource_kinds
        ):
            raise ValueError("Assessment includes an unsupported resource kind")
        for query in request.queries:
            if query.kind not in supported:
                raise ValueError("Assessment query includes an unsupported resource kind")
            if query.provider == "alicloud":
                self._authorize_alicloud(query.account_id, query.location)
            elif query.scope:
                await self.policy.authorize_scope(query.scope)
            else:
                validate_project(query.project)
        for kind in request.kubernetes_kinds or []:
            normalize_kind(kind)
        if any(
            not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location) for location in request.locations
        ):
            raise ValueError("Assessment locations must be explicit region or zone identifiers")
        job_id = await asyncio.to_thread(self.store.enqueue, actor, request.model_dump())
        LOG.info("tool=start_assessment caller_hash=%s job=%s", self._actor_hash(actor), job_id)
        return {
            "assessment_id": job_id,
            "status": "queued",
            "poll_tool": "get_assessment",
            "limits": self.capabilities()["limits"],
        }

    async def get_assessment(self, actor: str, identifier: str) -> dict[str, Any]:
        job = await asyncio.to_thread(self.store.get_job, actor, identifier)
        result = job.pop("result")
        if result is not None:
            job["summary"] = {key: value for key, value in result.items() if key != "findings"}
            job["stored_findings"] = len(result.get("findings", []))
        return job

    async def assessment_results(
        self, actor: str, identifier: str, *, page_size: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        self._page_size(page_size)
        job = await asyncio.to_thread(self.store.get_job, actor, identifier)
        result = job["result"]
        if result is None:
            return {
                "assessment_id": identifier,
                "status": job["status"],
                "items": [],
                "next_cursor": None,
            }
        binding = {"assessment_id": identifier}
        state = (
            self.store.decode_cursor(cursor, actor, "assessment_results", binding) if cursor else {}
        )
        offset = state.get("offset", 0)
        findings = result.get("findings", [])
        items = []
        total_bytes = 0
        for item in findings[offset : offset + page_size]:
            size = len(canonical_json(item).encode())
            if total_bytes + size > self.settings.max_response_bytes - 5000:
                if not items:
                    evidence_id = await asyncio.to_thread(self.store.put_evidence, actor, [item])
                    next_offset = offset + 1
                    next_cursor = (
                        self.store.encode_cursor(
                            actor, "assessment_results", binding, {"offset": next_offset}
                        )
                        if next_offset < len(findings)
                        else None
                    )
                    return {
                        "assessment_id": identifier,
                        "items": [],
                        "oversized_finding_index": offset,
                        "oversized_finding_evidence_id": evidence_id,
                        "next_cursor": next_cursor,
                        "response_truncated": True,
                        "message": "Retrieve the oversized finding through get_evidence with selected fields.",
                    }
                break
            items.append(item)
            total_bytes += size
        next_offset = offset + len(items)
        next_cursor = (
            self.store.encode_cursor(actor, "assessment_results", binding, {"offset": next_offset})
            if next_offset < len(findings)
            else None
        )
        return {
            "assessment_id": identifier,
            "status": job["status"],
            "summary": {key: value for key, value in result.items() if key != "findings"},
            "items": items,
            "offset": offset,
            "next_cursor": next_cursor,
            "total_findings": len(findings),
        }

    async def cancel_assessment(self, actor: str, identifier: str) -> dict[str, Any]:
        job = await asyncio.to_thread(self.store.cancel, actor, identifier)
        job.pop("result", None)
        return job

    async def _heartbeat_loop(self, job_id: str) -> None:
        while True:
            await asyncio.sleep(20)
            await asyncio.to_thread(self.store.heartbeat, job_id)

    async def _work_loop(self) -> None:
        while not self._stopping.is_set():
            job = await asyncio.to_thread(self.store.claim)
            if job is None:
                await asyncio.to_thread(self.store.cleanup)
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=2)
                except TimeoutError:
                    continue
                break
            heartbeat = asyncio.create_task(self._heartbeat_loop(job["id"]))
            try:
                result = await self._assessment(
                    job["actor"], AssessmentRequest.model_validate(job["request"]), job_id=job["id"]
                )
                status = "cancelled" if result["cancelled"] else "completed"
                await asyncio.to_thread(self.store.finish, job["id"], result, status=status)
                LOG.info(
                    "assessment=%s status=%s coverage_complete=%s",
                    job["id"],
                    status,
                    result["coverage_complete"],
                )
            except asyncio.CancelledError:
                # Leave a running lease. A restarted worker safely repeats the read-only job after lease expiry.
                raise
            except Exception as exc:
                LOG.error("assessment=%s failed exception_type=%s", job["id"], type(exc).__name__)
                await asyncio.to_thread(
                    self.store.finish,
                    job["id"],
                    status="failed",
                    error="Assessment execution failed; no all-clear conclusion is available",
                )
            finally:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat

    async def _assessment(
        self, actor: str, request: AssessmentRequest, *, job_id: str
    ) -> dict[str, Any]:
        started = utcnow()
        deadline = time.monotonic() + self.settings.max_scan_seconds
        counters: Counter = Counter()
        statuses: Counter = Counter()
        errors: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        evidence_pages: list[dict[str, Any]] = []
        warnings: set[str] = set()
        limits: set[str] = set()
        clusters: set[str] = set(request.clusters)
        cancelled = False
        definitions = list_checks()
        selected_ids = (
            set(request.check_ids)
            if request.check_ids is not None
            else {check.id for check in definitions}
        )
        selected_kinds = {check.resource_kind for check in definitions if check.id in selected_ids}
        gcp_kinds = list(
            dict.fromkeys(
                [kind for kind in request.resource_kinds if kind.startswith("gcp.")]
                if request.resource_kinds is not None
                else sorted(kind for kind in selected_kinds if kind in RESOURCE_SPECS)
            )
        )
        k8s_kinds = list(
            dict.fromkeys(
                normalize_kind(kind)
                for kind in (
                    request.kubernetes_kinds
                    if request.kubernetes_kinds is not None
                    else sorted(
                        kind.removeprefix("k8s.")
                        for kind in selected_kinds
                        if kind.startswith("k8s.")
                    )
                )
            )
        )
        if request.include_kubernetes and "gcp.container.clusters" not in gcp_kinds:
            gcp_kinds.append("gcp.container.clusters")

        async def can_continue() -> bool:
            nonlocal cancelled
            cancelled = cancelled or await asyncio.to_thread(
                self.store.heartbeat, job_id, dict(counters)
            )
            if time.monotonic() >= deadline:
                limits.add("max_scan_seconds")
            if counters["api_pages"] >= self.settings.max_scan_pages:
                limits.add("max_scan_pages")
            if counters["resources_examined"] >= self.settings.max_scan_resources:
                limits.add("max_scan_resources")
            if len(findings) >= 20_000:
                limits.add("max_stored_findings")
            return not limits and not cancelled

        async def reserve_page() -> bool:
            if not await can_continue():
                return False
            # No await between final budget check and reservation: all collectors share this event-loop counter.
            if counters["api_pages"] >= self.settings.max_scan_pages:
                limits.add("max_scan_pages")
                return False
            counters["api_pages"] += 1
            return True

        async def collect(query: ResourceQuery | KubernetesQuery, *, k8s: bool = False) -> None:
            async with self._call_slots:
                if not await can_continue():
                    counters["collections_not_started"] += 1
                    return
                counters["collections_attempted"] += 1
                token = None
                seen: set[str] = set()
                collection_error = False
                while await reserve_page():
                    try:
                        async with asyncio.timeout(max(0.01, deadline - time.monotonic())):
                            result = await (
                                self._raw_kubernetes(query, token)
                                if k8s
                                else self._raw_resource(query, token)
                            )
                    except Exception as exc:
                        target = query.cluster if k8s else f"{query.target}:{query.kind}"
                        result = CollectionResult(errors=[_error(target, exc)])
                    warnings.update(safe_text(warning) for warning in result.warnings)
                    errors.extend(
                        sanitize(error.model_dump(mode="json")) for error in result.errors
                    )
                    collection_error = collection_error or bool(result.errors)
                    remaining = max(
                        0, self.settings.max_scan_resources - counters["resources_examined"]
                    )
                    records = result.items[:remaining]
                    counters["resources_examined"] += len(records)
                    if len(records) < len(result.items):
                        limits.add("max_scan_resources")
                    if not k8s and query.kind == "gcp.container.clusters":
                        clusters.update(record.name for record in records)
                    checked = evaluate(records, request.check_ids)
                    statuses.update(check.status for check in checked)
                    counters["checks_evaluated"] += len(checked)
                    kept = [
                        check
                        for check in checked
                        if request.include_passes or check.status != "pass"
                    ]
                    evidence_id = None
                    if records:
                        evidence_id = await asyncio.to_thread(
                            self.store.put_evidence,
                            actor,
                            [project_record(record) for record in records],
                        )
                        evidence_pages.append(
                            {
                                "evidence_id": evidence_id,
                                "provider": query.provider,
                                "kind": query.kind,
                                "target": safe_text(query.cluster if k8s else query.target),
                                "resource_count": len(records),
                                "expires_in_seconds": self.settings.evidence_ttl_seconds,
                            }
                        )
                    if kept:
                        finding_budget = max(0, 20_000 - len(findings))
                        findings.extend(
                            sanitize(check.model_dump(mode="json")) | {"evidence_id": evidence_id}
                            for check in kept[:finding_budget]
                        )
                        if len(kept) > finding_budget:
                            limits.add("max_stored_findings")
                    if not result.next_page_token:
                        counters[
                            "collections_complete"
                            if not collection_error
                            else "collections_with_errors"
                        ] += 1
                        return
                    token = result.next_page_token
                    if token in seen:
                        errors.append(
                            {
                                "target": query.cluster if k8s else query.target,
                                "code": "PAGINATION_LOOP",
                                "message": "Upstream repeated a continuation token",
                                "retryable": False,
                            }
                        )
                        counters["collections_with_errors"] += 1
                        return
                    seen.add(token)
                counters["collections_incomplete"] += 1

        projects = set(request.projects)
        if request.scope:
            try:
                scope = await self.policy.authorize_scope(request.scope)
                if scope.startswith("projects/"):
                    projects.add(scope.split("/")[1])
                else:
                    token = None
                    seen_tokens: set[str] = set()
                    while await reserve_page():
                        async with asyncio.timeout(max(0.01, deadline - time.monotonic())):
                            discovered = await self.gcp.search_assets(
                                scope,
                                asset_types=["cloudresourcemanager.googleapis.com/Project"],
                                page_size=self.settings.max_page_size,
                                page_token=token,
                            )
                        errors.extend(
                            sanitize(error.model_dump(mode="json")) for error in discovered.errors
                        )
                        warnings.update(discovered.warnings)
                        for record in discovered.items:
                            project = record.name.rstrip("/").rsplit("/", 1)[-1]
                            validate_project(project)
                            projects.add(project)
                        if len(projects) > 1000:
                            limits.add("max_discovered_projects")
                            break
                        if not discovered.next_page_token:
                            break
                        token = discovered.next_page_token
                        if token in seen_tokens:
                            limits.add("discovery_pagination_loop")
                            break
                        seen_tokens.add(token)
            except Exception as exc:
                errors.append(sanitize(_error(request.scope, exc).model_dump(mode="json")))
        counters["projects_discovered"] = len(projects)
        for project in sorted(projects):
            if not await can_continue():
                counters["projects_not_started"] += 1
                continue
            counters["projects_attempted"] += 1
            queries: list[ResourceQuery] = []
            for kind in gcp_kinds:
                spec = RESOURCE_SPECS.get(kind)
                if spec is None:
                    errors.append(
                        {
                            "target": f"{project}:{kind}",
                            "code": "EXPLICIT_QUERY_REQUIRED",
                            "message": "Use AssessmentRequest.queries with the scope, operation, parent, resource ID and selectors advertised by capabilities for this query kind",
                            "retryable": False,
                        }
                    )
                    counters["collections_not_started"] += 1
                    continue
                if spec.location_mode == "required":
                    if not request.locations:
                        errors.append(
                            {
                                "target": f"{project}:{kind}",
                                "code": "LOCATION_REQUIRED",
                                "message": "An explicit region or zone is required; this collection was not checked",
                                "retryable": False,
                            }
                        )
                        counters["collections_not_started"] += 1
                    for location in request.locations:
                        queries.append(
                            ResourceQuery(
                                kind=kind,
                                project=project,
                                location=location,
                                page_size=self.settings.max_page_size,
                            )
                        )
                else:
                    queries.append(
                        ResourceQuery(
                            kind=kind, project=project, page_size=self.settings.max_page_size
                        )
                    )
            await asyncio.gather(*(collect(query) for query in queries))
        if request.queries:
            await asyncio.gather(*(collect(query) for query in request.queries))
        ali_capabilities = self.alicloud.capabilities() if self.alicloud else []
        ali_list_specs = {
            item["kind"]: item for item in ali_capabilities if item.get("operation") == "list"
        }
        ali_kinds = (
            [kind for kind in request.resource_kinds if kind.startswith("alicloud.")]
            if request.resource_kinds is not None
            else sorted(
                kind
                for kind in selected_kinds
                if kind in ali_list_specs and ali_list_specs[kind].get("default_scan", False)
            )
        )
        counters["accounts_discovered"] = len(set(request.accounts))
        for account in sorted(set(request.accounts)):
            if not await can_continue():
                counters["accounts_not_started"] += 1
                continue
            counters["accounts_attempted"] += 1
            ali_queries = []
            for kind in ali_kinds:
                spec = ali_list_specs.get(kind)
                if spec is None or not spec.get("default_scan", False):
                    errors.append(
                        {
                            "target": f"{account}:{kind}",
                            "code": "EXPLICIT_QUERY_REQUIRED",
                            "message": "This kind requires an explicit assessment query with its operation and parent/selectors",
                            "retryable": False,
                        }
                    )
                    counters["collections_not_started"] += 1
                    continue
                locations = request.locations if spec.get("location_required") else [None]
                if not locations:
                    errors.append(
                        {
                            "target": f"{account}:{kind}",
                            "code": "LOCATION_REQUIRED",
                            "message": "Supply Alibaba regions explicitly in locations; this collection was not checked",
                            "retryable": False,
                        }
                    )
                    counters["collections_not_started"] += 1
                for location in locations:
                    ali_queries.append(
                        ResourceQuery(
                            provider="alicloud",
                            account_id=account,
                            kind=kind,
                            location=location,
                            page_size=min(
                                self.settings.max_page_size, spec.get("max_page_size", 100)
                            ),
                        )
                    )
            await asyncio.gather(*(collect(query) for query in ali_queries))
            if request.include_kubernetes:
                clusters.update(
                    cluster
                    for cluster in self.settings.alicloud_kubernetes_clusters
                    if cluster_account(cluster)[0] == account
                    and (not request.locations or cluster_account(cluster)[1] in request.locations)
                )
        if request.include_kubernetes:
            counters["clusters_discovered"] = len(clusters)
            for cluster in sorted(clusters):
                if not await can_continue():
                    counters["clusters_not_started"] += 1
                    continue
                try:
                    provider = self._cluster_provider(cluster)
                except ValueError as exc:
                    errors.append(sanitize(_error("cluster_identity", exc).model_dump(mode="json")))
                    continue
                counters["clusters_attempted"] += 1
                await asyncio.gather(
                    *(
                        collect(
                            KubernetesQuery(
                                provider=provider,
                                cluster=cluster,
                                kind=kind,
                                page_size=min(500, self.settings.max_page_size),
                            ),
                            k8s=True,
                        )
                        for kind in k8s_kinds
                    )
                )
        if not counters["checks_evaluated"]:
            warnings.add(
                "No applicable checks were evaluated; this assessment does not establish a passing security posture."
            )
        cancelled = cancelled or await asyncio.to_thread(
            self.store.heartbeat, job_id, dict(counters)
        )
        complete = (
            not errors
            and not limits
            and not cancelled
            and not counters["collections_incomplete"]
            and not counters["collections_not_started"]
        )
        return {
            "started_at": started.isoformat(),
            "finished_at": utcnow().isoformat(),
            "coverage_complete": complete,
            "evaluation_has_unknowns": statuses["unknown"] > 0,
            "coverage": dict(counters),
            "check_status_counts": dict(statuses),
            "cancelled": cancelled,
            "limits_reached": sorted(limits),
            "errors": errors[:2000],
            "error_count": len(errors),
            "error_details_truncated": len(errors) > 2000,
            "warnings": sorted(warnings)[:200],
            "findings": findings,
            "evidence_pages": evidence_pages,
            "passed_results_omitted": not request.include_passes,
            "scope_note": "Coverage applies to the selected resource kinds, supplied locations and discovered targets, not every possible cloud security control.",
        }
