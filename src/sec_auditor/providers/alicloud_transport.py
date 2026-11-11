"""Account-verified Alibaba reads using official credential and signing SDKs.

The SDKs own credential refresh and cryptographic signing. HTTP remains here so
response size, redirects, concurrency, deadlines and error disclosure have the
same limits as the Google transport. No agent-supplied endpoint is accepted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import time
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from xml.etree import ElementTree

import httpx

from sec_auditor.config import Settings
from sec_auditor.transport import CloudAPIError

_ACCOUNT = re.compile(r"[0-9]{6,32}\Z")
_REGION = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)+\Z")
_IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:@-]{0,255}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\Z")
_SLS_PROJECT = re.compile(r"[a-z][a-z0-9-]{1,61}[a-z0-9]\Z")
_SLS_LOGSTORE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}\Z")
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+aliyuncs\.com\Z")
_SENSITIVE_ACTION = re.compile(
    r"(?:GetSecretValue|Decrypt|GenerateDataKey|GetObject|ListObjects|GetBucket$|"
    r"GetBucketV2|GetClusterKubeconfig|DescribeClusterUserKubeconfig|"
    r"GetInstanceConsole|GetInstanceScreenshot|DescribeUserData|GetUserData|"
    r"GetAccessKeySecret|GetCredentials|GetToken|DescribeDBInstanceSSL)",
    re.IGNORECASE,
)
_OSS_SUBRESOURCES = {
    "get_bucket_info": "bucketInfo",
    "get_bucket_acl": "acl",
    "get_bucket_policy": "policy",
    "get_bucket_encryption": "encryption",
    "get_bucket_versioning": "versioning",
    "get_bucket_logging": "logging",
    "get_bucket_lifecycle": "lifecycle",
    "get_bucket_cors": "cors",
    "get_bucket_referer": "referer",
    "get_bucket_public_access_block": "publicAccessBlock",
    "get_bucket_worm": "worm",
    "get_bucket_transfer_acceleration": "transferAcceleration",
}


@dataclass(frozen=True, repr=False)
class _CredentialSnapshot:
    """One atomic credential generation for both STS proof and the target read."""

    access_key_id: str = field(repr=False)
    access_key_secret: str = field(repr=False)
    security_token: str = field(default="", repr=False)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(
            (
                self.access_key_id + "\0" + self.access_key_secret + "\0" + self.security_token
            ).encode()
        ).hexdigest()

    def get_credentials(self) -> _CredentialSnapshot:
        return self

    def get_access_key_id(self) -> str:
        return self.access_key_id

    def get_access_key_secret(self) -> str:
        return self.access_key_secret

    def get_security_token(self) -> str:
        return self.security_token


def _json_body(content: bytes, *, allow_list: bool = False) -> Any:
    try:
        value = json.loads(content)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise CloudAPIError("INVALID_RESPONSE", "Alibaba API returned invalid JSON") from exc
    if not isinstance(value, dict) and not (allow_list and isinstance(value, list)):
        raise CloudAPIError("INVALID_RESPONSE", "Alibaba API returned an unexpected response shape")
    return value


def _xml_body(content: bytes) -> dict[str, Any]:
    # ElementTree does not resolve external entities. Also reject internal entity
    # declarations rather than relying on the parser's amplification threshold.
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        raise CloudAPIError("INVALID_RESPONSE", "OSS returned prohibited XML declarations")
    try:
        root = ElementTree.fromstring(content)
        count = 0

        def convert(node: ElementTree.Element, depth: int = 0) -> Any:
            nonlocal count
            count += 1
            if depth > 40 or count > 100_000:
                raise ValueError("XML structure limit")
            children = list(node)
            if not children:
                return node.text or ""
            value: dict[str, Any] = {}
            for child in children:
                name = child.tag.rsplit("}", 1)[-1]
                item = convert(child, depth + 1)
                if name in value:
                    if not isinstance(value[name], list):
                        value[name] = [value[name]]
                    value[name].append(item)
                else:
                    value[name] = item
            return value

        parsed = convert(root)
    except (ElementTree.ParseError, ValueError, RecursionError) as exc:
        raise CloudAPIError("INVALID_RESPONSE", "OSS returned invalid metadata XML") from exc
    return parsed if isinstance(parsed, dict) else {root.tag.rsplit("}", 1)[-1]: parsed}


class AlibabaRestClient:
    """One credential binding, checked against explicit account and region scopes.

    A deployment may configure several allowed IDs, but the current credential
    must belong to the requested account. This client never assumes a role based
    on an MCP argument and never treats Resource Directory membership as access.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        credentials: Any = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.settings = settings
        self._credentials = credentials
        self._credential_lock = asyncio.Lock()
        self._credential_task: asyncio.Task | None = None
        self._identity_lock = asyncio.Lock()
        self._identities: dict[str, tuple[str, float]] = {}
        self._bucket_proofs: dict[tuple[str, str, str, str], tuple[dict[str, Any], float]] = {}
        self._http = http_client or httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(
                max_connections=settings.max_concurrency,
                max_keepalive_connections=settings.max_concurrency,
            ),
        )
        self._owns_http = http_client is None
        self._global = asyncio.Semaphore(settings.max_concurrency)
        self._per_api: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(settings.per_api_concurrency)
        )
        self._rate_lock = asyncio.Lock()
        self._next_slot: dict[str, float] = {}

    def _account(self, account_id: str) -> None:
        if not isinstance(account_id, str) or not _ACCOUNT.fullmatch(account_id):
            raise ValueError("Alibaba account IDs must contain 6 to 32 digits")
        if account_id not in self.settings.allowed_alicloud_accounts:
            raise CloudAPIError("SCOPE_DENIED", "Alibaba account is outside the configured scope")

    def _region(self, region: str | None, *, required: bool = True) -> None:
        if not region:
            if required:
                raise ValueError("This Alibaba query requires an explicit region")
            return
        if not isinstance(region, str) or len(region) > 50 or not _REGION.fullmatch(region):
            raise ValueError("Invalid Alibaba region")
        if region not in self.settings.allowed_alicloud_regions:
            raise CloudAPIError("SCOPE_DENIED", "Alibaba region is outside the configured scope")

    async def _snapshot(self) -> _CredentialSnapshot:
        async with self._credential_lock:
            if self._credentials is None:
                try:
                    from alibabacloud_credentials.client import Client

                    self._credentials = Client()
                except Exception as exc:
                    raise CloudAPIError(
                        "AUTH_CONFIGURATION", "Alibaba default credentials are unavailable"
                    ) from exc
            if self._credential_task is None:
                self._credential_task = asyncio.create_task(
                    self._credentials.get_credential_async()
                )
            task = self._credential_task
            try:
                # Keep an unfinished refresh task after caller cancellation; a
                # later caller joins it instead of racing credential refresh.
                value = await asyncio.wait_for(
                    asyncio.shield(task), timeout=self.settings.request_timeout
                )
            except Exception as exc:
                raise CloudAPIError(
                    "UNAUTHENTICATED", "Alibaba credentials could not be obtained"
                ) from exc
            finally:
                if task.done():
                    self._credential_task = None
            access_key_id = getattr(value, "access_key_id", None)
            access_key_secret = getattr(value, "access_key_secret", None)
            security_token = getattr(value, "security_token", "") or ""
            if (
                not isinstance(access_key_id, str)
                or not access_key_id
                or not isinstance(access_key_secret, str)
                or not access_key_secret
                or not isinstance(security_token, str)
                or max(len(access_key_id), len(access_key_secret), len(security_token)) > 32_768
                or any(
                    ord(char) < 32 for char in access_key_id + access_key_secret + security_token
                )
            ):
                raise CloudAPIError(
                    "UNAUTHENTICATED", "Alibaba credentials returned an unsupported credential type"
                )
            return _CredentialSnapshot(access_key_id, access_key_secret, security_token)

    async def _authorize(self, account_id: str) -> _CredentialSnapshot:
        self._account(account_id)
        snapshot = await self._snapshot()
        key = snapshot.fingerprint
        async with self._identity_lock:
            known = self._identities.get(key)
            if known is None or known[1] <= time.monotonic():
                from sec_auditor.providers.alicloud_catalog import OPERATIONS

                operation = OPERATIONS["sts.identity"]
                if (
                    operation.action != "GetCallerIdentity"
                    or operation.endpoint != "sts.aliyuncs.com"
                ):
                    raise ValueError("Invalid built-in STS identity operation")
                identity = await self._openapi(operation, None, {}, snapshot)
                actual = identity.get("AccountId")
                if not isinstance(actual, str) or not _ACCOUNT.fullmatch(actual):
                    raise CloudAPIError(
                        "INVALID_IDENTITY", "STS returned no verifiable Alibaba account ID"
                    )
                if len(self._identities) >= 32:
                    self._identities.clear()
                known = (actual, time.monotonic() + self.settings.scope_cache_seconds)
                self._identities[key] = known
            if known[0] != account_id:
                raise CloudAPIError(
                    "SCOPE_DENIED",
                    "Alibaba credential identity does not match the requested account",
                )
        return snapshot

    @staticmethod
    def _validate_operation(operation: Any, parameters: dict[str, Any]) -> None:
        if (
            operation.method not in {"GET", "POST"}
            or operation.style not in {"RPC", "ROA", "OSS"}
            or not re.fullmatch(r"(?:Get|List|Describe|Lookup)[a-zA-Z0-9]+", operation.action)
            or _SENSITIVE_ACTION.search(operation.action)
        ):
            raise ValueError("Operation is outside the Alibaba read-only catalog")
        if set(parameters) - set(operation.parameters):
            raise ValueError("Unsupported parameters for this Alibaba operation")
        for key, value in parameters.items():
            if not isinstance(key, str) or not isinstance(value, (str, int, bool, float)):
                raise ValueError("Alibaba parameters must be scalar values")
            if len(str(value)) > 8192 or any(ord(char) < 32 for char in str(value)):
                raise ValueError(
                    "Alibaba query parameter is too long or contains control characters"
                )
        for key in getattr(operation, "path_parameters", ()):
            if not isinstance(parameters.get(key), str) or not _IDENTIFIER.fullmatch(
                parameters[key]
            ):
                raise ValueError("Invalid Alibaba resource path identifier")

    @staticmethod
    def _endpoint(operation: Any, region: str | None) -> str:
        overrides = getattr(operation, "endpoint_overrides", {})
        host = overrides.get(region, operation.endpoint.format(region=region or ""))
        if not _HOST.fullmatch(host) or len(host) > 253:
            raise ValueError("Only fixed Alibaba API endpoints are permitted")
        return host

    async def execute(
        self,
        account_id: str,
        operation_id: str,
        *,
        region: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from sec_auditor.providers.alicloud_catalog import OPERATIONS

        operation = OPERATIONS.get(operation_id)
        if operation is None:
            raise ValueError("Unknown Alibaba operation")
        parameters = dict(parameters or {})
        self._validate_operation(operation, parameters)
        self._region(region, required=operation.region_required)
        if "RegionId" in parameters and parameters["RegionId"] != region:
            raise ValueError("RegionId must match the authorized query region")
        if any(
            key in parameters
            for key in ("OwnerId", "ResourceOwnerId", "OwnerAccount", "ResourceOwnerAccount")
        ):
            raise ValueError("Caller-supplied Alibaba owner overrides are prohibited")
        if operation.action == "LookupEvents":
            self._actiontrail_window(parameters)
        snapshot = await self._authorize(account_id)
        if operation.style == "OSS":
            return await self._oss(operation, account_id, region, parameters, snapshot)
        return await self._openapi(operation, region, parameters, snapshot)

    def _actiontrail_window(self, parameters: dict[str, Any]) -> None:
        try:
            start = datetime.fromisoformat(str(parameters["StartTime"]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(parameters["EndTime"]).replace("Z", "+00:00"))
            if (
                start.tzinfo is None
                or end.tzinfo is None
                or not 0 < (end - start).total_seconds() <= self.settings.max_log_hours * 3600
                or end.timestamp() > time.time() + 300
            ):
                raise ValueError("Invalid window")
        except (KeyError, ValueError, OverflowError) as exc:
            raise ValueError(
                "ActionTrail requires an explicit bounded, timezone-aware time window"
            ) from exc

    async def _openapi(
        self,
        operation: Any,
        region: str | None,
        parameters: dict[str, Any],
        snapshot: _CredentialSnapshot,
    ) -> dict[str, Any]:
        from alibabacloud_tea_openapi.client import DaraRequest, Utils

        host = self._endpoint(operation, region)
        path_parameters = getattr(operation, "path_parameters", ())
        path = operation.path.format(**{key: parameters[key] for key in path_parameters})
        if (
            not path.startswith("/")
            or "//" in path
            or any(c in path for c in "\\%?#")
            or any(part in {".", ".."} for part in path.split("/"))
        ):
            raise ValueError("Invalid built-in Alibaba resource path")
        query = {key: value for key, value in parameters.items() if key not in path_parameters}
        request = DaraRequest()
        request.protocol = "https"
        request.method = operation.method
        request.pathname = path
        request.query = Utils.query(query)
        request.headers = {
            "host": host,
            "x-acs-version": operation.version,
            "x-acs-action": operation.action,
            "x-acs-date": Utils.get_timestamp(),
            "x-acs-signature-nonce": Utils.get_nonce(),
            "accept": "application/json",
            "user-agent": "sec-auditor/0.2",
        }
        payload_hash = Utils.hash(b"", "ACS3-HMAC-SHA256").hex()
        request.headers["x-acs-content-sha256"] = payload_hash
        if snapshot.security_token:
            request.headers["x-acs-accesskey-id"] = snapshot.access_key_id
            request.headers["x-acs-security-token"] = snapshot.security_token
        request.headers["Authorization"] = Utils.get_authorization(
            request,
            "ACS3-HMAC-SHA256",
            payload_hash,
            snapshot.access_key_id,
            snapshot.access_key_secret,
        )
        content, _ = await self._send(
            operation.method, f"https://{host}{path}", headers=request.headers, params=request.query
        )
        return _json_body(content)

    async def _rate_limit(self, host: str) -> None:
        async with self._rate_lock:
            now = time.monotonic()
            slot = max(now, self._next_slot.get(host, now))
            self._next_slot[host] = slot + 1 / self.settings.requests_per_second
        if slot > now:
            await asyncio.sleep(slot - now)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, Any],
        body: bytes | None = None,
    ) -> tuple[bytes, httpx.Headers]:
        host = httpx.URL(url).host
        async with self._global, self._per_api[host]:
            for attempt in range(self.settings.request_retries + 1):
                await self._rate_limit(host)
                try:
                    async with asyncio.timeout(self.settings.request_timeout):
                        async with self._http.stream(
                            method,
                            url,
                            headers=headers,
                            params=params,
                            content=body,
                            follow_redirects=False,
                        ) as response:
                            status = response.status_code
                            if not 200 <= status < 300:
                                retryable = status in {429, 500, 502, 503, 504}
                                if retryable and attempt < self.settings.request_retries:
                                    await asyncio.sleep(min(2**attempt, 8) + random.random() / 4)
                                    continue
                                code = {
                                    401: "UNAUTHENTICATED",
                                    403: "PERMISSION_DENIED",
                                    404: "NOT_FOUND",
                                    429: "RESOURCE_EXHAUSTED",
                                }.get(status, "UPSTREAM_ERROR")
                                raise CloudAPIError(
                                    code,
                                    f"Alibaba API returned HTTP {status}",
                                    status_code=status,
                                    retryable=retryable,
                                )
                            content = bytearray()
                            async for chunk in response.aiter_bytes(chunk_size=65_536):
                                content.extend(chunk)
                                if len(content) > self.settings.max_api_response_bytes:
                                    raise CloudAPIError(
                                        "RESPONSE_TOO_LARGE",
                                        "Alibaba API response exceeded the configured byte limit",
                                    )
                            return bytes(content), response.headers
                except (httpx.HTTPError, TimeoutError) as exc:
                    if attempt < self.settings.request_retries:
                        await asyncio.sleep(min(2**attempt, 8) + random.random() / 4)
                        continue
                    raise CloudAPIError(
                        "UNAVAILABLE", "Alibaba API request failed or timed out", retryable=True
                    ) from exc
        raise CloudAPIError("UNAVAILABLE", "Alibaba API request did not complete", retryable=True)

    async def _oss_request(
        self,
        method: str,
        host: str,
        bucket: str,
        region: str,
        query: dict[str, Any],
        snapshot: _CredentialSnapshot,
    ) -> dict[str, Any]:
        import oss2

        target = f"{bucket}.{host}" if bucket else host
        request = oss2.http.Request(
            "GET",
            f"https://{target}/",
            params=query,
            headers={
                "Accept": "application/json" if method == "get_bucket_policy" else "application/xml"
            },
            app_name="sec-auditor/0.2",
            region=region,
            product="oss",
        )
        oss2.ProviderAuthV4(snapshot)._sign_request(request, bucket, "")
        content, _ = await self._send(
            "GET",
            request.url,
            headers={key: value for key, value in request.headers.items() if value is not None},
            params=request.params,
        )
        return _json_body(content) if method == "get_bucket_policy" else _xml_body(content)

    async def _oss(
        self,
        operation: Any,
        account_id: str,
        region: str | None,
        parameters: dict[str, Any],
        snapshot: _CredentialSnapshot,
    ) -> dict[str, Any]:
        assert region is not None  # OSS regions are always explicit in this catalog.
        host = self._endpoint(operation, region)
        if host != f"oss-{region}.aliyuncs.com":
            raise ValueError("Unsupported OSS endpoint")
        method = getattr(operation, "oss_method", None)
        if method == "list_buckets":
            if set(parameters) - {"Marker", "MaxKeys", "Prefix"}:
                raise ValueError("Unsupported OSS bucket listing parameter")
            maximum = parameters.get("MaxKeys", 100)
            if not str(maximum).isdigit() or not 1 <= int(maximum) <= 1000:
                raise ValueError("Invalid OSS bucket page size")
            query = {"max-keys": str(maximum)}
            if parameters.get("Marker"):
                query["marker"] = str(parameters["Marker"])
            if parameters.get("Prefix"):
                query["prefix"] = str(parameters["Prefix"])
            result = await self._oss_request(method, host, "", region, query, snapshot)
            owner = result.get("Owner")
            if not isinstance(owner, dict) or owner.get("ID") != account_id:
                raise CloudAPIError(
                    "SCOPE_DENIED", "OSS bucket listing owner could not be verified"
                )
            buckets = result.get("Buckets", {})
            values = buckets.get("Bucket", []) if isinstance(buckets, dict) else []
            if isinstance(values, dict):
                values = [values]
            if not isinstance(values, list):
                raise CloudAPIError("INVALID_RESPONSE", "OSS returned invalid bucket metadata")
            return {
                "Buckets": [
                    item
                    for item in values
                    if isinstance(item, dict) and item.get("Location") == f"oss-{region}"
                ],
                "IsTruncated": str(result.get("IsTruncated", "false")).lower() == "true",
                "NextMarker": result.get("NextMarker", ""),
            }
        if method not in _OSS_SUBRESOURCES:
            raise ValueError("Only explicitly registered OSS bucket metadata reads are permitted")
        bucket = parameters.get("BucketName")
        if not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket):
            raise ValueError("Invalid OSS bucket name")
        key = (snapshot.fingerprint, account_id, region, bucket)
        proof = self._bucket_proofs.get(key)
        if proof is None or proof[1] <= time.monotonic():
            metadata = await self._oss_request(
                "get_bucket_info", host, bucket, region, {"bucketInfo": ""}, snapshot
            )
            info = metadata.get("Bucket")
            owner = info.get("Owner") if isinstance(info, dict) else None
            if (
                not isinstance(info, dict)
                or info.get("Name") != bucket
                or info.get("Location") != f"oss-{region}"
                or not isinstance(owner, dict)
                or owner.get("ID") != account_id
            ):
                raise CloudAPIError(
                    "SCOPE_DENIED", "OSS bucket account and region could not be verified"
                )
            proof = (metadata, time.monotonic() + self.settings.scope_cache_seconds)
            if len(self._bucket_proofs) >= 2048:
                self._bucket_proofs.clear()
            self._bucket_proofs[key] = proof
        if method == "get_bucket_info":
            return proof[0]
        return await self._oss_request(
            method, host, bucket, region, {_OSS_SUBRESOURCES[method]: ""}, snapshot
        )

    async def query_logs(
        self,
        account_id: str,
        *,
        region: str,
        project: str,
        logstore: str,
        start_time: int,
        end_time: int,
        query: str = "",
        offset: int = 0,
        line: int = 100,
    ) -> dict[str, Any]:
        """Read a bounded slice from one operator-registered SLS logstore.

        No SQL, cross-logstore queries, arbitrary search expression or analytics
        are accepted. The caller routes by a configured logstore key; this method
        independently checks the complete target tuple before signing a request.
        """
        from aliyun.log.auth import AuthV4

        self._account(account_id)
        self._region(region)
        if not _SLS_PROJECT.fullmatch(project) or not _SLS_LOGSTORE.fullmatch(logstore):
            raise ValueError("Invalid SLS project or logstore name")
        if query:
            raise ValueError("SLS arbitrary queries and SQL are not supported")
        configured = getattr(self.settings, "alicloud_logstores", {})
        if not any(
            (item.account_id, item.region, item.project, item.logstore)
            == (account_id, region, project, logstore)
            for item in configured.values()
        ):
            raise CloudAPIError(
                "SCOPE_DENIED", "SLS logstore is not registered for this deployment"
            )
        if (
            type(start_time) is not int
            or type(end_time) is not int
            or start_time < 0
            or not 0 < end_time - start_time <= self.settings.max_log_hours * 3600
            or end_time > int(time.time()) + 300
            or type(offset) is not int
            or not 0 <= offset <= 100_000
            or type(line) is not int
            or not 1 <= line <= min(self.settings.max_page_size, 100)
        ):
            raise ValueError("SLS time window or pagination exceeds the configured bounds")
        snapshot = await self._authorize(account_id)
        host = f"{project}.{region}.log.aliyuncs.com"
        path = f"/logstores/{logstore}/logs"
        body = json.dumps(
            {
                "from": start_time,
                "to": end_time,
                "line": line,
                "offset": offset,
                "query": "*",
                "reverse": True,
                "powerSql": False,
                "highlight": False,
            },
            separators=(",", ":"),
        ).encode()
        headers = {
            "Host": host,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/json",
            "x-log-apiversion": "0.6.0",
            "x-log-bodyrawsize": str(len(body)),
            "User-Agent": "sec-auditor/0.2",
        }
        AuthV4(snapshot, region).sign_request("POST", path, {}, headers, body)
        content, response_headers = await self._send(
            "POST", f"https://{host}{path}", headers=headers, params={}, body=body
        )
        content = self._sls_decode(content, response_headers)
        payload = _json_body(content)
        records, metadata = payload.get("data"), payload.get("meta")
        if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
            raise CloudAPIError("INVALID_RESPONSE", "SLS returned an unexpected log response shape")
        if not isinstance(metadata, dict) or metadata.get("hasSQL") not in (None, False):
            raise CloudAPIError("INVALID_RESPONSE", "SLS returned unexpected query metadata")
        if len(records) > line:
            raise CloudAPIError(
                "INVALID_RESPONSE", "SLS returned more entries than the requested bound"
            )
        progress = metadata.get("progress", "Incomplete")
        if progress not in {"Complete", "Incomplete"}:
            progress = "Incomplete"
        # Incomplete results must be retried at the same offset, never skipped.
        next_offset = (
            offset
            if progress == "Incomplete"
            else (offset + len(records) if len(records) == line else None)
        )
        return {
            "logs": records,
            "count": len(records),
            "progress": progress,
            "next_offset": next_offset,
            "has_more": next_offset is not None,
        }

    def _sls_decode(self, content: bytes, headers: httpx.Headers) -> bytes:
        """Decode GetLogsV2 without trusting the declared uncompressed size.

        SLS uses x-log-compresstype and the official SDK accepts both zlib's
        wrapper and gzip for its gzip mode. A strict output cap prevents a small
        compressed response from allocating an unbounded decompression result.
        Standard Content-Encoding was already decoded by httpx under the same
        output-byte cap in _send.
        """
        compression = headers.get("x-log-compresstype", "").lower()
        if compression not in {"", "gzip", "deflate"}:
            raise CloudAPIError("INVALID_RESPONSE", "SLS returned unsupported compression")
        raw_size = headers.get("x-log-bodyrawsize")
        if raw_size is not None:
            try:
                declared = int(raw_size)
                if declared < 0:
                    raise ValueError
            except (ValueError, TypeError) as exc:
                raise CloudAPIError(
                    "INVALID_RESPONSE", "SLS returned an invalid uncompressed size"
                ) from exc
            if declared > self.settings.max_api_response_bytes:
                raise CloudAPIError(
                    "RESPONSE_TOO_LARGE",
                    "SLS uncompressed response exceeds the configured byte limit",
                )
        if not compression or headers.get("content-encoding", "").lower() in {"gzip", "deflate"}:
            return content
        try:
            decoder = zlib.decompressobj(zlib.MAX_WBITS | 32)
            result = decoder.decompress(content, self.settings.max_api_response_bytes + 1)
            if len(result) > self.settings.max_api_response_bytes or decoder.unconsumed_tail:
                raise CloudAPIError(
                    "RESPONSE_TOO_LARGE",
                    "SLS uncompressed response exceeds the configured byte limit",
                )
            if not decoder.eof or decoder.unused_data:
                raise ValueError("Incomplete or concatenated compression stream")
        except (zlib.error, ValueError) as exc:
            raise CloudAPIError("INVALID_RESPONSE", "SLS returned invalid compressed data") from exc
        return result

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()
