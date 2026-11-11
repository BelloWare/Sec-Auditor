"""Native GCP configuration collectors with bounded, explicit read routes.

The application authorizes a scope before invoking this adapter. This adapter
additionally validates every path component. Raw observations stay inside the
service; the output projection is applied by the application boundary.
"""

import asyncio
import re
from typing import Any

from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.providers.catalog import (
    ASSET_KIND_MAP,
    RESOURCE_SPECS,
    SAFE_ASSET_TYPES,
    ResourceSpec,
)
from sec_auditor.providers.gcp_queries import QUERY_SPECS, QuerySpec, query_capabilities
from sec_auditor.transport import CloudAPIError, GoogleRestClient

PROJECT_PATTERN = re.compile(r"(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})\Z")
LOCATION_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
DATASET_PATTERN = re.compile(r"[A-Za-z0-9_]{1,1024}\Z")
ACCOUNT_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}@[a-z0-9.-]+\.gserviceaccount\.com\Z"
)


def validate_project(project: str) -> str:
    if not isinstance(project, str) or not PROJECT_PATTERN.fullmatch(project):
        raise ValueError("project must be a bare GCP project ID or project number")
    return project


def validate_scope(scope: str) -> str:
    if not isinstance(scope, str):
        raise ValueError("scope must identify a project, folder, or organization")
    parts = scope.split("/")
    if len(parts) != 2:
        raise ValueError("scope must identify a project, folder, or organization")
    if parts[0] == "projects":
        validate_project(parts[1])
    elif parts[0] not in {"folders", "organizations"} or not re.fullmatch(r"[0-9]{1,20}", parts[1]):
        raise ValueError("scope must identify a project, folder, or organization")
    return scope


def _validate_page(page_size: int, page_token: str | None) -> None:
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 1000:
        raise ValueError("page_size must be between 1 and 1000")
    if page_token is not None and (
        not isinstance(page_token, str)
        or len(page_token) > 16384
        or any(ord(c) < 32 for c in page_token)
    ):
        raise ValueError("Invalid page token")


def _location(spec: ResourceSpec, value: str | None) -> str | None:
    if spec.location_mode == "none":
        if value is not None:
            raise ValueError(f"{spec.kind} does not accept location")
        return None
    if value is None:
        if spec.location_mode == "required":
            raise ValueError(f"{spec.kind} requires an explicit location")
        return "-" if spec.location_mode == "wildcard" else "global"
    if value == "-" and spec.location_mode == "wildcard":
        return value
    if not isinstance(value, str) or not LOCATION_PATTERN.fullmatch(value):
        raise ValueError("Invalid location")
    return value


def _as_list(value: Any, field: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CloudAPIError("INVALID_RESPONSE", f"Expected an object array in {field}")
    return value


def _collection_error(exc: CloudAPIError, target: str) -> CollectionError:
    return CollectionError(
        target=target, code=exc.code, message=exc.message, retryable=exc.retryable
    )


def _native_token(response: dict[str, Any]) -> str | None:
    token = response.get("nextPageToken")
    if token is not None and not isinstance(token, str):
        raise CloudAPIError("INVALID_RESPONSE", "Invalid upstream nextPageToken")
    return token or None


class GCPProvider:
    name = "gcp"

    def __init__(self, client: GoogleRestClient):
        self.client = client

    def capabilities(self) -> list[dict[str, Any]]:
        return query_capabilities()

    async def query_resources(
        self,
        kind: str,
        project: str,
        *,
        location: str | None = None,
        parent: str | None = None,
        resource_id: str | None = None,
        selectors: dict[str, str] | None = None,
        operation: str = "list",
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        """Execute one reviewed configuration query at an authorized root scope.

        The second argument accepts a bare project identifier or a canonical
        projects/..., folders/... or organizations/... scope. Scope authorization
        is the service's responsibility; child ownership is checked here too.
        """
        scope = (
            validate_scope(project) if "/" in project else f"projects/{validate_project(project)}"
        )
        _validate_page(page_size, page_token)
        if operation not in {"list", "get"}:
            raise ValueError("operation must be list or get")
        spec = QUERY_SPECS.get((kind, operation))
        if spec is None:
            if operation != "list" or kind not in RESOURCE_SPECS:
                raise ValueError("Unsupported GCP resource kind or operation")
            if not scope.startswith("projects/"):
                raise ValueError(f"{kind} only supports a project scope")
            if parent is not None or resource_id is not None or selectors:
                raise ValueError(
                    "This list query does not accept parent, resource_id, or selectors"
                )
            return await self.list_resources(
                kind,
                scope.split("/", 1)[1],
                location=location,
                page_size=page_size,
                page_token=page_token,
            )
        if scope.split("/", 1)[0] not in spec.scopes:
            raise ValueError(f"{kind} {operation} does not support this scope type")
        if selectors is not None and (
            not isinstance(selectors, dict)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in selectors.items()
            )
        ):
            raise ValueError("selectors must map strings to strings")
        supplied = selectors or {}
        if set(supplied) - set(spec.selectors):
            raise ValueError("Unsupported selector for this query")
        selected = {**spec.defaults, **supplied}
        for key, pattern in spec.selectors.items():
            if key not in selected or not re.fullmatch(pattern, selected[key]):
                raise ValueError(f"Invalid or missing selector: {key}")
        if spec.needs_resource_id:
            if (
                not isinstance(resource_id, str)
                or not re.fullmatch(spec.resource_pattern, resource_id)
                or resource_id in {".", ".."}
            ):
                raise ValueError("Invalid or missing resource_id")
        elif resource_id is not None:
            raise ValueError("This query does not accept resource_id")
        if spec.parent_suffix is None and parent is not None:
            raise ValueError("This query does not accept parent")
        if spec.pagination == "singleton" and page_token is not None:
            raise ValueError("Singleton reads do not accept a page token")

        selected_location, compute_path = self._query_location(spec, location, selected)
        target = f"{scope}:{kind}:{operation}"
        try:
            validated_parent = await self._query_parent(spec, scope, parent)
            replacements = {
                "scope": scope,
                "location": selected_location,
                "parent": validated_parent,
                "resource_id": resource_id,
                "compute_path": compute_path,
                "attachment": f"cloudresourcemanager.googleapis.com%2F{scope.replace('/', '%2F')}",
                **selected,
            }
            url = spec.url.format(**replacements)
            params = {
                key: value.format(**replacements) if isinstance(value, str) else value
                for key, value in spec.params.items()
            }
            for selector, parameter in spec.selector_params.items():
                params[parameter] = selected[selector]
            if spec.special == "scc" and selected["state"] != "ALL":
                params["filter"] = f'state="{selected["state"]}"'
            effective_size = min(page_size, spec.max_page_size)
            offset = self._offset(page_token) if spec.pagination == "client" else 0
            if spec.pagination == "native":
                params[spec.page_size_key] = effective_size
                if page_token:
                    params["pageToken"] = page_token
            if spec.special in {"bucket", "bucket_policy"}:
                await self._verify_bucket(scope, resource_id)
            elif spec.special == "hierarchical_get":
                await self._verify_firewall_policy(scope, resource_id)
            if spec.special == "sa_policy":
                response = await self.client.post_read(
                    url, json={}, params={"options.requestedPolicyVersion": 3}
                )
            elif spec.special == "crm_policy":
                response = await self.client.post_read(
                    url, json={"options": {"requestedPolicyVersion": 3}}
                )
            else:
                response = await self.client.get(url, params=params or None)
            result = CollectionResult(
                metadata={
                    "scope": scope,
                    "kind": kind,
                    "operation": operation,
                    "location": selected_location,
                    "parent": validated_parent,
                    "pagination": spec.pagination,
                    "requested_page_size": page_size,
                    "effective_page_size": effective_size,
                    "freshness": "live",
                }
            )
            self._partial_errors(response, target, result)
            raw = (
                [response]
                if spec.items_key is None
                else _as_list(response.get(spec.items_key), spec.items_key)
            )
            if spec.special == "vulnerabilities":
                rejected = sum(item.get("kind") != "VULNERABILITY" for item in raw)
                raw = [item for item in raw if item.get("kind") == "VULNERABILITY"]
                if rejected:
                    result.errors.append(
                        CollectionError(
                            target=target,
                            code="UNEXPECTED_OCCURRENCE_KIND",
                            message="Upstream returned non-vulnerability occurrences; they were discarded.",
                        )
                    )
            if spec.pagination == "client":
                raw.sort(key=lambda item: str(item.get("name") or item.get("id") or ""))
                total = len(raw)
                raw = raw[offset : offset + effective_size]
                if offset + effective_size < total:
                    result.next_page_token = f"offset:{offset + effective_size}"
                result.metadata.update(
                    {"upstream_items": total, "pagination_consistency": "best_effort"}
                )
                result.warnings.append(
                    "Upstream has no pagination; continuation re-reads the collection and may observe changes."
                )
            elif spec.pagination == "native":
                result.next_page_token = _native_token(response)
                if len(raw) > effective_size:
                    result.metadata["upstream_page_size_exceeded"] = True
                    result.warnings.append(
                        "Upstream returned more items than requested; all observed items are retained subject to the application response budget."
                    )
            if spec.special == "deny":
                result.metadata["detail_level"] = (
                    "metadata_without_rules" if operation == "list" else "policy_rules"
                )
                result.metadata["policy_semantics"] = "direct_deny_policy"
                if operation == "list":
                    result.warnings.append(
                        "Deny-policy list omits rules; get each policy and inspect relevant ancestor policies."
                    )
            if kind in {
                "gcp.iam.policy",
                "gcp.storage.bucketIamPolicy",
                "gcp.iam.serviceAccountIamPolicy",
            }:
                result.metadata.update(
                    {"policy_semantics": "direct_allow_policy", "requested_policy_version": 3}
                )
            for item in raw:
                result.items.append(
                    self._query_record(
                        spec, scope, item, url, selected_location, validated_parent, resource_id
                    )
                )
            return result
        except CloudAPIError as exc:
            return CollectionResult(
                errors=[_collection_error(exc, target)],
                metadata={"scope": scope, "kind": kind, "operation": operation},
            )

    @staticmethod
    def _query_location(
        spec: QuerySpec, location: str | None, selectors: dict[str, str]
    ) -> tuple[str | None, str | None]:
        if spec.compute_scopes:
            location_type = selectors.get("location_type", spec.compute_scopes[0])
            if location_type == "global":
                if location not in {None, "global"}:
                    raise ValueError(
                        "Global Compute resources do not accept a regional/zonal location"
                    )
                return "global", "global"
            if (
                not isinstance(location, str)
                or not LOCATION_PATTERN.fullmatch(location)
                or location == "global"
            ):
                raise ValueError("A concrete location is required for a regional/zonal Compute get")
            if location_type == "zones" and not re.fullmatch(
                r"[a-z]+(?:-[a-z0-9]+)*[0-9]-[a-z]", location
            ):
                raise ValueError("A zone is required for this Compute get")
            if location_type == "regions" and not re.fullmatch(
                r"[a-z]+(?:-[a-z0-9]+)*[0-9]", location
            ):
                raise ValueError("A region is required for this Compute get")
            return location, f"{location_type}/{location}"
        selected = _location(spec, location)
        if (
            selected == "global"
            and spec.location_mode == "required"
            and spec.kind == "gcp.compute.effectiveFirewalls"
        ):
            raise ValueError("A zone is required for effective firewall rules")
        if spec.kind == "gcp.compute.effectiveFirewalls" and not re.fullmatch(
            r"[a-z]+(?:-[a-z0-9]+)*[0-9]-[a-z]", selected or ""
        ):
            raise ValueError("A zone is required for effective firewall rules")
        return selected, None

    async def _query_parent(self, spec: QuerySpec, scope: str, parent: str | None) -> str | None:
        if spec.parent_suffix is None:
            return None
        if not isinstance(parent, str) or len(parent) > 4096 or "/" not in parent:
            raise ValueError("This query requires a canonical parent resource name")
        if spec.special == "access_policy_parent":
            if not re.fullmatch(spec.parent_suffix, parent):
                raise ValueError("Parent must identify a numeric access policy")
            await self._verify_access_policy(scope, parent)
            return parent
        parts = parent.split("/", 2)
        if len(parts) != 3 or not re.fullmatch(spec.parent_suffix, parts[2]):
            raise ValueError("Parent does not match this query's allowed resource type")
        if spec.kind == "gcp.iam.workloadIdentityProviders" and not parts[1].isdigit():
            raise ValueError(
                "Workload identity provider parent requires the authorized project number"
            )
        parent_scope = "/".join(parts[:2])
        if parent_scope != scope:
            if not scope.startswith("projects/") or parts[0] != "projects":
                raise ValueError("Parent is outside the authorized scope")
            authorized_project = scope.split("/")[1]
            if parts[1].isdigit() and not authorized_project.isdigit():
                number = await self._project_number(authorized_project)
                matches = parent_scope == f"projects/{number}"
            elif authorized_project.isdigit() and not parts[1].isdigit():
                identity = await self.client.get(
                    f"https://cloudresourcemanager.googleapis.com/v3/{scope}"
                )
                matches = identity.get("name") == scope and identity.get("projectId") == parts[1]
            else:
                matches = False
            if not matches:
                raise ValueError("Parent is outside the authorized scope")
        return parent

    async def _verify_bucket(self, scope: str, bucket: str) -> None:
        """Use a project-scoped membership read before the globally named bucket."""
        response = await self.client.get(
            "https://storage.googleapis.com/storage/v1/b",
            params={
                "project": scope.split("/")[1],
                "prefix": bucket,
                "maxResults": 1000,
                "projection": "noAcl",
            },
        )
        if not any(item.get("name") == bucket for item in _as_list(response.get("items"), "items")):
            raise CloudAPIError(
                "RESOURCE_SCOPE_MISMATCH",
                "Bucket membership in the authorized project could not be established; no bucket detail or IAM read was made.",
            )

    async def _verify_firewall_policy(self, scope: str, policy_id: str) -> None:
        response = await self.client.get(
            "https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies",
            params={"parentId": scope, "filter": f'id = "{policy_id}"', "maxResults": 500},
        )
        if not any(
            str(item.get("id")) == policy_id or str(item.get("name")) == policy_id
            for item in _as_list(response.get("items"), "items")
        ):
            raise CloudAPIError(
                "RESOURCE_SCOPE_MISMATCH",
                "Firewall policy membership in the authorized parent could not be established; no global policy get was made.",
            )

    async def _verify_access_policy(self, scope: str, parent: str) -> None:
        """A global Access Context Manager policy ID is not an authority boundary."""
        token: str | None = None
        seen: set[str] = set()
        for _ in range(10):
            params: dict[str, Any] = {"parent": scope, "pageSize": 100}
            if token:
                params["pageToken"] = token
            response = await self.client.get(
                "https://accesscontextmanager.googleapis.com/v1/accessPolicies", params=params
            )
            if any(
                item.get("name") == parent
                for item in _as_list(response.get("accessPolicies"), "accessPolicies")
            ):
                return
            token = _native_token(response)
            if not token or token in seen:
                break
            seen.add(token)
        raise CloudAPIError(
            "RESOURCE_SCOPE_MISMATCH",
            "Access-policy ownership could not be established within the bounded organization listing; no nested policy configuration was read.",
        )

    @staticmethod
    def _query_record(
        spec: QuerySpec,
        scope: str,
        item: dict[str, Any],
        url: str,
        location: str | None,
        parent: str | None,
        resource_id: str | None,
    ) -> ResourceRecord:
        item = dict(item)
        if spec.special == "vulnerabilities":
            allowed = {
                "name",
                "resourceUri",
                "noteName",
                "kind",
                "remediation",
                "createTime",
                "updateTime",
                "vulnerability",
            }
            item = {key: value for key, value in item.items() if key in allowed}
        project = scope.split("/")[1] if scope.startswith("projects/") else None
        if spec.kind in RESOURCE_SPECS and project:
            record = GCPProvider._record(RESOURCE_SPECS[spec.kind], project, item, url, location)
            record.freshness = "live"
            return record
        name = str(item.get("selfLink") or item.get("name") or item.get("id") or "")
        if spec.kind == "gcp.securitycenter.findings":
            name = str(item.get("finding", {}).get("name") or name)
        if not name:
            name = f"{parent or scope}/{spec.kind}" + (f"/{resource_id}" if resource_id else "")
        for field in ("privateKeyData", "publicKeyData", "attestation"):
            item.pop(field, None)
        return ResourceRecord(
            kind=spec.kind,
            name=name,
            project=project,
            location=None if location == "-" else location,
            data=item,
            freshness="live",
            source=url,
        )

    async def list_resources(
        self,
        kind: str,
        project: str,
        *,
        location: str | None = None,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        """Read one page; never hide pagination or scope failures.

        Native pagination tokens are passed through unchanged. GKE's unpaged
        list method is locally paginated using a clearly marked offset token;
        it is a best-effort observation, not a cross-request snapshot.
        """
        project = validate_project(project)
        _validate_page(page_size, page_token)
        if kind not in RESOURCE_SPECS:
            raise ValueError("Unsupported GCP resource kind")
        spec = RESOURCE_SPECS[kind]
        selected_location = _location(spec, location)
        target = f"projects/{project}:{kind}"
        if selected_location:
            target += f":{selected_location}"
        try:
            if spec.pagination == "policy":
                if page_token:
                    raise ValueError("IAM policy reads do not accept a page token")
                return await self.get_iam_policy(f"projects/{project}")
            if spec.pagination == "keys":
                return await self._service_account_keys(project, page_size, page_token)
            if spec.pagination == "singleton" and page_token:
                raise ValueError("Singleton reads do not accept a page token")
            local_offset = self._offset(page_token) if spec.pagination == "client" else 0

            endpoint_project = (
                await self._project_number(project) if spec.project_number else project
            )
            url = spec.url.format(project=endpoint_project, location=selected_location)
            params = {
                key: value.format(project=project) if isinstance(value, str) else value
                for key, value in spec.params.items()
            }
            effective_size = min(page_size, spec.max_page_size)
            if spec.pagination == "native":
                params[spec.page_size_key] = effective_size
                if page_token:
                    params["pageToken"] = page_token
            response = await self.client.get(url, params=params or None)
            result = CollectionResult(
                metadata={
                    "scope": f"projects/{project}",
                    "kind": kind,
                    "location": selected_location,
                    "pagination": spec.pagination,
                    "requested_page_size": page_size,
                    "effective_page_size": effective_size,
                    "freshness": spec.freshness,
                }
            )
            self._partial_errors(response, target, result)

            if spec.pagination == "singleton":
                result.items = [self._record(spec, project, response, url, selected_location)]
                return result

            raw: list[tuple[dict[str, Any], str | None]] = []
            if spec.aggregation_key:
                scopes = response.get(spec.items_key, {})
                if not isinstance(scopes, dict):
                    raise CloudAPIError("INVALID_RESPONSE", "Expected an aggregated scope map")
                for scope, entries in sorted(scopes.items()):
                    if not isinstance(entries, dict):
                        raise CloudAPIError("INVALID_RESPONSE", "Invalid aggregated scope")
                    self._partial_errors(entries, f"projects/{project}/{scope}", result)
                    for item in _as_list(entries.get(spec.aggregation_key), spec.aggregation_key):
                        raw.append((item, scope))
            else:
                raw = [
                    (item, None) for item in _as_list(response.get(spec.items_key), spec.items_key)
                ]

            if spec.pagination == "client":
                offset = local_offset
                raw.sort(
                    key=lambda pair: (
                        str(pair[0].get("location", "")),
                        str(pair[0].get("name", "")),
                    )
                )
                total = len(raw)
                raw = raw[offset : offset + effective_size]
                if offset + effective_size < total:
                    result.next_page_token = f"offset:{offset + effective_size}"
                result.metadata.update(
                    {"upstream_items": total, "pagination_consistency": "best_effort"}
                )
                result.warnings.append(
                    "Upstream has no pagination; continuation re-reads the collection and may observe changes."
                )
            else:
                result.next_page_token = _native_token(response)
                if len(raw) > effective_size:
                    result.metadata["upstream_page_size_exceeded"] = True
                    result.warnings.append(
                        "Upstream returned more items than the requested page size; all observed items are retained subject to the application response budget."
                    )

            if kind == "gcp.bigquery.datasets":
                await self._enrich_datasets(project, raw, result)
            for item, scope in raw:
                result.items.append(
                    self._record(spec, project, item, url, scope or selected_location)
                )
            return result
        except CloudAPIError as exc:
            return CollectionResult(errors=[_collection_error(exc, target)])

    async def _project_number(self, project: str) -> str:
        if project.isdigit():
            return project
        response = await self.client.get(
            f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}"
        )
        name = response.get("name", "")
        match = re.fullmatch(r"projects/([0-9]{1,20})", name) if isinstance(name, str) else None
        if not match or response.get("projectId", project) != project:
            raise CloudAPIError(
                "INVALID_RESPONSE", "Could not resolve the authorized project number"
            )
        return match.group(1)

    @staticmethod
    def _offset(page_token: str | None) -> int:
        if not page_token:
            return 0
        match = re.fullmatch(r"offset:([0-9]{1,7})", page_token)
        if not match:
            raise ValueError("Invalid local pagination token")
        return int(match.group(1))

    @staticmethod
    def _record(
        spec: ResourceSpec, project: str, item: dict[str, Any], url: str, scope: str | None
    ) -> ResourceRecord:
        item = dict(item)
        name = str(item.get("selfLink") or item.get("name") or item.get("id") or "")
        location = item.get("location") or item.get("region") or item.get("zone") or scope
        if isinstance(location, str):
            location = location.rsplit("/", 1)[-1]
            if location in {"-", "global"}:
                location = None if location == "-" else location
        else:
            location = scope
        if spec.kind == "gcp.container.clusters":
            short_name = str(item.get("name", ""))
            if short_name and "/" not in short_name and location:
                name = f"projects/{project}/locations/{location}/clusters/{short_name}"
        elif spec.kind == "gcp.storage.buckets":
            name = f"//storage.googleapis.com/{item.get('name', '')}"
        elif spec.kind == "gcp.bigquery.datasets":
            dataset = item.get("datasetReference", {}).get("datasetId")
            name = f"projects/{project}/datasets/{dataset}" if dataset else name
        elif spec.kind == "gcp.securitycenter.findings":
            name = str(item.get("finding", {}).get("name") or name)
        if not name:
            name = f"projects/{project}/{spec.kind}"
        # Key contents are outside this adapter even before the central output filter.
        for field in ("privateKeyData", "publicKeyData"):
            item.pop(field, None)
        return ResourceRecord(
            kind=spec.kind,
            name=name,
            project=project,
            location=location,
            data=item,
            freshness=spec.freshness,
            source=url,
        )

    @staticmethod
    def _partial_errors(response: dict[str, Any], target: str, result: CollectionResult) -> None:
        for field in ("unreachable", "unreachables", "missingZones"):
            missing = response.get(field, [])
            if not isinstance(missing, list):
                raise CloudAPIError("INVALID_RESPONSE", f"Invalid {field} response")
            for scope in missing:
                result.errors.append(
                    CollectionError(
                        target=f"{target}/{scope}",
                        code="UNREACHABLE_SCOPE",
                        message="Upstream could not read this location; coverage is incomplete.",
                        retryable=True,
                    )
                )
        warning = response.get("warning")
        if isinstance(warning, dict):
            code = str(warning.get("code", "UPSTREAM_WARNING"))
            if code != "NO_RESULTS_ON_PAGE":
                result.warnings.append(f"{target}: upstream warning {code}")
                result.errors.append(
                    CollectionError(
                        target=target,
                        code="PARTIAL_RESPONSE",
                        message=f"Upstream returned {code}; verify coverage.",
                        retryable=True,
                    )
                )
        if response.get("error"):
            result.errors.append(
                CollectionError(
                    target=target,
                    code="PARTIAL_RESPONSE",
                    message="Upstream reported a scoped collection error.",
                    retryable=True,
                )
            )

    async def _enrich_datasets(
        self, project: str, raw: list[tuple[dict[str, Any], str | None]], result: CollectionResult
    ) -> None:
        async def enrich(item: dict[str, Any]) -> None:
            reference = item.get("datasetReference", {})
            dataset = reference.get("datasetId") if isinstance(reference, dict) else None
            if not isinstance(dataset, str) or not DATASET_PATTERN.fullmatch(dataset):
                raise CloudAPIError(
                    "INVALID_RESPONSE", "Invalid dataset identifier in list response"
                )
            referenced_project = reference.get("projectId")
            if referenced_project and referenced_project != project:
                raise CloudAPIError("INVALID_RESPONSE", "Dataset response has a different project")
            target = f"projects/{project}/datasets/{dataset}"
            try:
                full = await self.client.get(
                    f"https://bigquery.googleapis.com/bigquery/v2/{target}"
                )
                item.clear()
                item.update(full)
            except CloudAPIError as exc:
                result.errors.append(_collection_error(exc, target))
                item["_collection"] = {"detail_level": "summary", "enrichment_failed": True}

        # Global/API concurrency is enforced by the shared transport, not by each call.
        await asyncio.gather(*(enrich(item) for item, _ in raw))

    async def _service_account_keys(
        self, project: str, page_size: int, page_token: str | None
    ) -> CollectionResult:
        accounts = await self.list_resources(
            "gcp.iam.serviceAccounts",
            project,
            page_size=min(page_size, 20),
            page_token=page_token,
        )
        result = CollectionResult(
            next_page_token=accounts.next_page_token,
            errors=list(accounts.errors),
            warnings=list(accounts.warnings),
            metadata={
                "scope": f"projects/{project}",
                "page_unit": "service_accounts",
                "accounts_examined": 0,
            },
        )
        spec = RESOURCE_SPECS["gcp.iam.serviceAccountKeys"]

        async def read(account: ResourceRecord) -> list[ResourceRecord]:
            email = account.data.get("email")
            if not isinstance(email, str) or not ACCOUNT_PATTERN.fullmatch(email):
                result.errors.append(
                    CollectionError(
                        target=account.name,
                        code="INVALID_RESPONSE",
                        message="Invalid service account email in list response.",
                    )
                )
                return []
            url = f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{email}/keys"
            try:
                response = await self.client.get(url, params={"keyTypes": "USER_MANAGED"})
                keys = _as_list(response.get("keys"), "keys")
                result.metadata["accounts_examined"] += 1
                return [self._record(spec, project, key, url, None) for key in keys]
            except CloudAPIError as exc:
                result.errors.append(_collection_error(exc, account.name))
                return []

        for records in await asyncio.gather(*(read(account) for account in accounts.items)):
            result.items.extend(records)
        return result

    async def get_iam_policy(self, scope: str) -> CollectionResult:
        scope = validate_scope(scope)
        url = f"https://cloudresourcemanager.googleapis.com/v3/{scope}:getIamPolicy"
        try:
            response = await self.client.post_read(
                url, json={"options": {"requestedPolicyVersion": 3}}
            )
            return CollectionResult(
                items=[
                    ResourceRecord(
                        kind="gcp.iam.policy",
                        name=scope,
                        project=scope.split("/")[1] if scope.startswith("projects/") else None,
                        data=response,
                        source=url,
                    )
                ],
                metadata={
                    "scope": scope,
                    "policy_semantics": "direct_allow_policy",
                    "requested_policy_version": 3,
                },
            )
        except CloudAPIError as exc:
            return CollectionResult(errors=[_collection_error(exc, scope)])

    async def search_assets(
        self,
        scope: str,
        query: str = "",
        asset_types: list[str] | None = None,
        *,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        scope = validate_scope(scope)
        _validate_page(page_size, page_token)
        if not isinstance(query, str) or len(query) > 4096:
            raise ValueError("Asset query must be at most 4096 characters")
        types = self._asset_types(asset_types)
        params: dict[str, Any] = {"pageSize": min(page_size, 500), "assetTypes": types}
        if query:
            params["query"] = query
        if page_token:
            params["pageToken"] = page_token
        url = f"https://cloudasset.googleapis.com/v1/{scope}:searchAllResources"
        try:
            response = await self.client.get(url, params=params)
            return CollectionResult(
                items=[
                    ResourceRecord(
                        kind="gcp.asset.search",
                        name=str(item.get("name", "")),
                        project=self._asset_project(item),
                        data=item,
                        freshness="inventory",
                        source=url,
                    )
                    for item in _as_list(response.get("results"), "results")
                ],
                next_page_token=_native_token(response),
                metadata={
                    "scope": scope,
                    "asset_types": types,
                    "freshness": "inventory",
                    "query": query,
                },
                warnings=[
                    "Cloud Asset Inventory is eventually consistent; use native configuration reads when freshness matters."
                ],
            )
        except CloudAPIError as exc:
            return CollectionResult(errors=[_collection_error(exc, scope)])

    async def search_iam_policies(
        self,
        scope: str,
        query: str = "",
        asset_types: list[str] | None = None,
        *,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        """Search indexed resource policies, preserving conditional bindings.

        A nonempty query can select individual bindings; the result is not a
        complete policy and must not be interpreted as an effective-access test.
        """
        scope = validate_scope(scope)
        _validate_page(page_size, page_token)
        if not isinstance(query, str) or len(query) > 4096:
            raise ValueError("IAM query must be at most 4096 characters")
        params: dict[str, Any] = {"pageSize": min(page_size, 500)}
        if asset_types is not None:
            params["assetTypes"] = self._asset_types(asset_types)
        if query:
            params["query"] = query
        if page_token:
            params["pageToken"] = page_token
        url = f"https://cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies"
        try:
            response = await self.client.get(url, params=params)
            records = []
            for item in _as_list(response.get("results"), "results"):
                policy = item.get("policy", {})
                if not isinstance(policy, dict):
                    raise CloudAPIError("INVALID_RESPONSE", "Expected IAM policy object")
                payload = dict(policy)
                payload["_collection"] = {
                    "query_filtered_bindings": bool(query),
                    "asset_type": item.get("assetType"),
                }
                records.append(
                    ResourceRecord(
                        kind="gcp.iam.policy",
                        name=str(item.get("resource", "")),
                        project=self._asset_project(item),
                        data=payload,
                        freshness="inventory",
                        source=url,
                    )
                )
            return CollectionResult(
                items=records,
                next_page_token=_native_token(response),
                metadata={
                    "scope": scope,
                    "query": query,
                    "freshness": "inventory",
                    "policy_semantics": "indexed_matching_bindings",
                    "complete_policies": not bool(query),
                },
                warnings=[
                    "Indexed IAM search is eventually consistent. Query filters may return only matching bindings; results do not calculate effective access or deny-policy effects."
                ],
            )
        except CloudAPIError as exc:
            return CollectionResult(errors=[_collection_error(exc, scope)])

    async def list_assets(
        self,
        scope: str,
        asset_types: list[str] | None = None,
        *,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        scope = validate_scope(scope)
        _validate_page(page_size, page_token)
        types = self._asset_types(asset_types)
        params: dict[str, Any] = {
            "pageSize": page_size,
            "assetTypes": types,
            "contentType": "RESOURCE",
        }
        if page_token:
            params["pageToken"] = page_token
        url = f"https://cloudasset.googleapis.com/v1/{scope}/assets"
        try:
            response = await self.client.get(url, params=params)
            records = []
            for asset in _as_list(response.get("assets"), "assets"):
                asset_type = asset.get("assetType")
                if asset_type not in types:
                    raise CloudAPIError(
                        "INVALID_RESPONSE", "Unexpected resource type in asset response"
                    )
                resource = asset.get("resource", {})
                payload = resource.get("data", {}) if isinstance(resource, dict) else {}
                if not isinstance(payload, dict):
                    raise CloudAPIError("INVALID_RESPONSE", "Expected asset resource data object")
                payload = dict(payload)
                payload["_asset"] = {
                    "assetType": asset_type,
                    "updateTime": asset.get("updateTime"),
                    "ancestors": asset.get("ancestors", []),
                }
                records.append(
                    ResourceRecord(
                        kind=ASSET_KIND_MAP[asset_type],
                        name=str(asset.get("name", "")),
                        project=self._asset_project(asset),
                        data=payload,
                        freshness="inventory",
                        source=url,
                    )
                )
            return CollectionResult(
                items=records,
                next_page_token=_native_token(response),
                metadata={
                    "scope": scope,
                    "asset_types": types,
                    "read_time": response.get("readTime"),
                    "freshness": "inventory",
                },
                warnings=[
                    "Cloud Asset Inventory snapshots may lag live state; supported types are explicitly allowlisted."
                ],
            )
        except CloudAPIError as exc:
            return CollectionResult(errors=[_collection_error(exc, scope)])

    @staticmethod
    def _asset_project(asset: dict[str, Any]) -> str | None:
        project = asset.get("project")
        if isinstance(project, str) and project.startswith("projects/"):
            return project.split("/")[-1]
        for ancestor in asset.get("ancestors", []):
            if isinstance(ancestor, str) and ancestor.startswith("projects/"):
                return ancestor.split("/")[-1]
        return None

    @staticmethod
    def _asset_types(asset_types: list[str] | None) -> list[str]:
        if asset_types is None:
            return sorted(SAFE_ASSET_TYPES)
        if not isinstance(asset_types, list) or not 1 <= len(asset_types) <= 100:
            raise ValueError("asset_types must contain between 1 and 100 explicit supported types")
        if any(
            not isinstance(value, str) or value not in SAFE_ASSET_TYPES for value in asset_types
        ):
            raise ValueError(
                "Unsupported asset type; resource-content reads use an explicit allowlist"
            )
        return sorted(set(asset_types))
