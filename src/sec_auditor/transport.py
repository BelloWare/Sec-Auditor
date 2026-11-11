"""Bounded, keyless, read-only Google REST transport using official ADC."""

import asyncio
import json
import random
import re
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

import google.auth
import httpx
from google.auth.transport.requests import Request

from sec_auditor.config import Settings

GOOGLE_HOSTS = frozenset(
    {
        "cloudasset.googleapis.com",
        "compute.googleapis.com",
        "container.googleapis.com",
        "storage.googleapis.com",
        "iam.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "sqladmin.googleapis.com",
        "run.googleapis.com",
        "cloudfunctions.googleapis.com",
        "artifactregistry.googleapis.com",
        "bigquery.googleapis.com",
        "pubsub.googleapis.com",
        "dns.googleapis.com",
        "logging.googleapis.com",
        "orgpolicy.googleapis.com",
        "secretmanager.googleapis.com",
        "cloudkms.googleapis.com",
        "securitycenter.googleapis.com",
        "osconfig.googleapis.com",
        "serviceusage.googleapis.com",
        "monitoring.googleapis.com",
        "accesscontextmanager.googleapis.com",
        "binaryauthorization.googleapis.com",
        "networkmanagement.googleapis.com",
        "kmsinventory.googleapis.com",
        "containeranalysis.googleapis.com",
    }
)
READ_POSTS = (
    re.compile(r"https://logging\.googleapis\.com/v2/entries:list\Z"),
    re.compile(
        r"https://cloudresourcemanager\.googleapis\.com/v3/(projects|folders|organizations)/[a-zA-Z0-9-]+:getIamPolicy\Z"
    ),
    re.compile(
        r"https://iam\.googleapis\.com/v1/projects/[a-zA-Z0-9-]+/serviceAccounts/[a-zA-Z0-9_.@-]+:getIamPolicy\Z"
    ),
)
FORBIDDEN_PATH = re.compile(
    r"(?:/objects(?:/|$)|/o(?:/|$)|:access(?:$|/)|/secrets/[^/]+/versions(?:/|$)|"
    r"getSerialPortOutput|getScreenshot|getGuestAttributes|/tabledata(?:/|$)|"
    r"/tables/[^/]+/data(?:/|$)|/queries(?:/|$)|:readRows|:pull|:streamingPull|"
    r":export|:import|/serviceAccounts/[^/]+/keys/[^/]+$)",
    re.IGNORECASE,
)


class CloudAPIError(Exception):
    def __init__(self, code: str, message: str, *, status_code: int = 0, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retryable = retryable


def validate_google_url(method: str, url: str) -> str:
    parsed = urlsplit(url)
    encoded_deny_attachment = parsed.hostname == "iam.googleapis.com" and re.fullmatch(
        r"/v2/policies/cloudresourcemanager\.googleapis\.com%2F(?:projects|folders|organizations)%2F[a-zA-Z0-9-]+/denypolicies(?:/[a-zA-Z0-9-]+)?",
        parsed.path,
    )
    if (
        parsed.scheme != "https"
        or parsed.hostname not in GOOGLE_HOSTS
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or ("%" in parsed.path and not encoded_deny_attachment)
        or "\\" in url
        or any(ord(c) < 32 for c in url)
        or "//" in parsed.path
        or any(p in {".", ".."} for p in parsed.path.split("/"))
    ):
        raise ValueError("Only fixed Google API endpoints are permitted")
    if parsed.hostname == "storage.googleapis.com" and not re.fullmatch(
        r"/storage/v1/b(?:/[a-z0-9][a-z0-9._-]{1,220}[a-z0-9](?:/iam|/acl)?)?", parsed.path
    ):
        raise ValueError("Only bucket configuration and bucket IAM reads are permitted")
    if parsed.hostname == "containeranalysis.googleapis.com" and not re.fullmatch(
        r"/v1/projects/[a-zA-Z0-9-]+/occurrences(?:/[a-zA-Z0-9-]+)?", parsed.path
    ):
        raise ValueError("Only Container Analysis occurrence metadata is permitted")
    if FORBIDDEN_PATH.search(parsed.path):
        raise ValueError("Data-content or diagnostic endpoint is outside the audit boundary")
    if method == "POST":
        if not any(pattern.fullmatch(url) for pattern in READ_POSTS):
            raise ValueError("Only explicitly allowlisted read RPCs may use POST")
    elif method != "GET":
        raise ValueError("Mutating HTTP methods are prohibited")
    return parsed.hostname


class GoogleRestClient:
    def __init__(
        self,
        settings: Settings,
        *,
        credentials: Any = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.settings = settings
        self._credentials = credentials
        self._auth_lock = asyncio.Lock()
        self._refresh_request: Request | None = None
        self._refresh_task: asyncio.Task | None = None
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

    async def access_token(self, force_refresh: bool = False) -> str:
        async with self._auth_lock:
            if self._credentials is None:
                try:
                    self._credentials, _ = await asyncio.to_thread(
                        google.auth.default,
                        scopes=["https://www.googleapis.com/auth/cloud-platform"],
                        quota_project_id=self.settings.quota_project,
                    )
                except google.auth.exceptions.GoogleAuthError as exc:
                    raise CloudAPIError(
                        "AUTH_CONFIGURATION", "Application Default Credentials are unavailable"
                    ) from exc
            joined_refresh = self._refresh_task is not None
            if self._refresh_task is not None:
                await self._wait_for_refresh()
            if (force_refresh and not joined_refresh) or not self._credentials.valid:
                if self._refresh_request is None:
                    self._refresh_request = Request()
                self._refresh_task = asyncio.create_task(
                    asyncio.to_thread(self._credentials.refresh, self._refresh_request)
                )
                await self._wait_for_refresh()
            if not self._credentials.token:
                raise CloudAPIError(
                    "UNAUTHENTICATED", "Google credentials returned no access token"
                )
            return str(self._credentials.token)

    async def _wait_for_refresh(self) -> None:
        assert self._refresh_task is not None
        task = self._refresh_task
        try:
            # Cancelling an async caller cannot stop a running requests thread. Keep the
            # refresh task and let subsequent callers join it instead of racing a second refresh.
            await asyncio.wait_for(asyncio.shield(task), timeout=self.settings.request_timeout)
        except (google.auth.exceptions.GoogleAuthError, TimeoutError) as exc:
            raise CloudAPIError(
                "UNAUTHENTICATED", "Google credentials could not be refreshed"
            ) from exc
        finally:
            if task.done():
                self._refresh_task = None

    async def _rate_limit(self, host: str) -> None:
        async with self._rate_lock:
            now = time.monotonic()
            slot = max(now, self._next_slot.get(host, now))
            self._next_slot[host] = slot + 1 / self.settings.requests_per_second
        if slot > now:
            await asyncio.sleep(slot - now)

    async def get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("GET", url, params=params)

    async def post_read(
        self, url: str, json: dict[str, Any], params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request("POST", url, body=json, params=params)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        host = validate_google_url(method, url)
        if params and any(
            k.lower() in {"alt", "access_token", "key", "uploadtype", "$httpmethod"} for k in params
        ):
            raise ValueError("Unsafe Google API query parameter")
        async with self._global, self._per_api[host]:
            refreshed = False
            for attempt in range(self.settings.request_retries + 2):
                await self._rate_limit(host)
                token = await self.access_token()
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "User-Agent": "sec-auditor/0.1",
                }
                if self.settings.quota_project:
                    headers["x-goog-user-project"] = self.settings.quota_project
                try:
                    async with self._http.stream(
                        method, url, params=params, json=body, headers=headers
                    ) as response:
                        if response.status_code == 401 and not refreshed:
                            refreshed = True
                            await self.access_token(force_refresh=True)
                            continue
                        if (
                            response.status_code in {429, 500, 502, 503, 504}
                            and attempt < self.settings.request_retries
                        ):
                            await asyncio.sleep(min(2**attempt, 8) + random.random() / 4)
                            continue
                        if not 200 <= response.status_code < 300:
                            code = {
                                401: "UNAUTHENTICATED",
                                403: "PERMISSION_DENIED",
                                404: "NOT_FOUND",
                                429: "RESOURCE_EXHAUSTED",
                            }.get(response.status_code, "UPSTREAM_ERROR")
                            raise CloudAPIError(
                                code,
                                f"Google API returned HTTP {response.status_code}",
                                status_code=response.status_code,
                                retryable=response.status_code in {429, 500, 502, 503, 504},
                            )
                        chunks: list[bytes] = []
                        size = 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > self.settings.max_api_response_bytes:
                                raise CloudAPIError(
                                    "RESPONSE_TOO_LARGE",
                                    "API response exceeded the configured byte limit; use a smaller page",
                                )
                            chunks.append(chunk)
                        try:
                            payload = json.loads(b"".join(chunks))
                        except (ValueError, UnicodeDecodeError) as exc:
                            raise CloudAPIError(
                                "INVALID_RESPONSE", "Google API returned invalid JSON"
                            ) from exc
                        if not isinstance(payload, dict):
                            raise CloudAPIError(
                                "INVALID_RESPONSE", "Expected an API object response"
                            )
                        return payload
                except httpx.TimeoutException as exc:
                    if attempt < self.settings.request_retries:
                        await asyncio.sleep(0.25 * (attempt + 1))
                        continue
                    raise CloudAPIError(
                        "DEADLINE_EXCEEDED", "Google API request timed out", retryable=True
                    ) from exc
                except httpx.RequestError as exc:
                    if attempt < self.settings.request_retries:
                        await asyncio.sleep(0.25 * (attempt + 1))
                        continue
                    raise CloudAPIError(
                        "UNAVAILABLE", "Google API network request failed", retryable=True
                    ) from exc
            raise CloudAPIError("UNAUTHENTICATED", "Google API rejected refreshed credentials")

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()
        if self._refresh_request is not None:
            self._refresh_request.session.close()
