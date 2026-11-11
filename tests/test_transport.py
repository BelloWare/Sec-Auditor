"""Credential and HTTP boundaries use an in-process fake Google endpoint."""

import asyncio
import json

import httpx
import pytest

from sec_auditor.config import Settings
from sec_auditor.transport import CloudAPIError, GoogleRestClient, validate_google_url

API = "https://compute.googleapis.com/compute/v1/projects/project-a/aggregated/instances"


class Credentials:
    token = "access-token"
    valid = True

    def __init__(self):
        self.refreshes = 0

    def refresh(self, request):
        self.refreshes += 1
        self.token = "refreshed-token"
        self.valid = True


def client_for(handler, **settings):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    credentials = Credentials()
    config = Settings(
        allowed_organizations=["123"], requests_per_second=100, request_retries=0, **settings
    )
    client = GoogleRestClient(config, credentials=credentials, http_client=http)
    return client, http, credentials


@pytest.mark.parametrize(
    "url",
    [
        "http://compute.googleapis.com/compute/v1/projects/project-a",
        "https://compute.googleapis.com.evil.test/compute/v1/projects/project-a",
        "https://user:password@compute.googleapis.com/compute/v1/projects/project-a",
        "https://compute.googleapis.com:444/compute/v1/projects/project-a",
        "https://compute.googleapis.com/compute/v1/projects/../project-a",
        "https://compute.googleapis.com/compute/v1/projects/%2e%2e/project-a",
        "https://compute.googleapis.com//compute/v1/projects/project-a",
        "https://compute.googleapis.com/compute/v1/projects/project-a?alt=media",
        "https://compute.googleapis.com/compute/v1/projects/project-a#fragment",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    ],
)
def test_url_canonicalization_and_host_boundary(url):
    with pytest.raises(ValueError):
        validate_google_url("GET", url)


@pytest.mark.parametrize(
    "url",
    [
        "https://storage.googleapis.com/storage/v1/b/bucket-name/o",
        "https://storage.googleapis.com/storage/v1/b/bucket-name/o/object-name",
        "https://storage.googleapis.com/download/storage/v1/b/bucket-name/o/object-name",
        "https://storage.googleapis.com/bucket-name/object-name",
        "https://secretmanager.googleapis.com/v1/projects/project-a/secrets/credential/versions/latest:access",
        "https://secretmanager.googleapis.com/v1/projects/project-a/secrets/credential/versions",
        "https://compute.googleapis.com/compute/v1/projects/project-a/zones/us-central1-a/instances/vm/getSerialPortOutput",
        "https://compute.googleapis.com/compute/v1/projects/project-a/zones/us-central1-a/instances/vm/getScreenshot",
        "https://compute.googleapis.com/compute/v1/projects/project-a/zones/us-central1-a/instances/vm/getGuestAttributes",
        "https://bigquery.googleapis.com/bigquery/v2/projects/project-a/datasets/dataset/tables/table/data",
        "https://bigquery.googleapis.com/bigquery/v2/projects/project-a/queries/job-id",
        "https://pubsub.googleapis.com/v1/projects/project-a/subscriptions/sub:pull",
        "https://iam.googleapis.com/v1/projects/project-a/serviceAccounts/sa@example.iam.gserviceaccount.com/keys/1234",
    ],
)
def test_content_and_diagnostic_reads_are_forbidden(url):
    with pytest.raises(ValueError):
        validate_google_url("GET", url)


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def test_unsupported_methods_are_rejected(method):
    with pytest.raises(ValueError):
        validate_google_url(method, API)


def test_only_named_read_post_rpcs_are_allowed():
    assert (
        validate_google_url("POST", "https://logging.googleapis.com/v2/entries:list")
        == "logging.googleapis.com"
    )
    assert (
        validate_google_url(
            "POST", "https://cloudresourcemanager.googleapis.com/v3/organizations/123:getIamPolicy"
        )
        == "cloudresourcemanager.googleapis.com"
    )
    for url in (
        "https://compute.googleapis.com/compute/v1/projects/project-a/zones/us-central1-a/instances",
        "https://cloudresourcemanager.googleapis.com/v3/organizations/123:setIamPolicy",
        "https://logging.googleapis.com/v2/entries:write",
    ):
        with pytest.raises(ValueError):
            validate_google_url("POST", url)


@pytest.mark.parametrize("param", ["alt", "access_token", "key", "uploadType", "$httpMethod"])
async def test_unsafe_query_parameters_rejected_before_token_or_request(param):
    calls = []
    client, http, _ = client_for(
        lambda request: calls.append(request) or httpx.Response(200, json={})
    )
    async with http:
        with pytest.raises(ValueError):
            await client.get(API, {param: "bad"})
    assert calls == []


async def test_bearer_and_quota_headers_set_on_metadata_reads():
    seen = []
    client, http, _ = client_for(
        lambda request: seen.append(request) or httpx.Response(200, json={"items": {}}),
        quota_project="quota-project",
    )
    async with http:
        assert await client.get(API, {"maxResults": 10}) == {"items": {}}
    assert seen[0].headers["authorization"] == "Bearer access-token"
    assert seen[0].headers["x-goog-user-project"] == "quota-project"
    assert seen[0].url.params["maxResults"] == "10"


async def test_permission_denied_not_retried_or_echoed():
    calls = []
    client, http, _ = client_for(
        lambda request: (
            calls.append(request)
            or httpx.Response(403, json={"error": {"message": "SENSITIVE ERROR BODY"}})
        )
    )
    async with http:
        with pytest.raises(CloudAPIError) as caught:
            await client.get(API)
    assert caught.value.code == "PERMISSION_DENIED"
    assert caught.value.retryable is False
    assert "SENSITIVE" not in str(caught.value)
    assert len(calls) == 1


async def test_401_refreshes_once_and_uses_new_token():
    seen = []

    def handler(request):
        seen.append(request.headers["authorization"])
        return (
            httpx.Response(401, json={})
            if len(seen) == 1
            else httpx.Response(200, json={"ok": True})
        )

    client, http, credentials = client_for(handler)
    async with http:
        assert await client.get(API) == {"ok": True}
    assert seen == ["Bearer access-token", "Bearer refreshed-token"]
    assert credentials.refreshes == 1


async def test_cancelled_caller_does_not_start_concurrent_credential_refreshes():
    import threading

    started = threading.Event()
    release = threading.Event()

    class SlowCredentials(Credentials):
        valid = False

        def refresh(self, request):
            self.refreshes += 1
            started.set()
            assert release.wait(3)
            self.valid = True
            self.token = "fresh-token"

    credentials = SlowCredentials()
    config = Settings(allowed_projects=["project-a"])
    client = GoogleRestClient(config, credentials=credentials)
    first = asyncio.create_task(client.access_token())
    assert await asyncio.to_thread(started.wait, 2)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    second = asyncio.create_task(client.access_token(force_refresh=True))
    await asyncio.sleep(0)
    release.set()
    assert await second == "fresh-token"
    assert credentials.refreshes == 1
    await client.aclose()


async def test_repeated_401_stops_after_one_refresh():
    calls = []
    client, http, credentials = client_for(
        lambda request: calls.append(request) or httpx.Response(401, json={})
    )
    async with http:
        with pytest.raises(CloudAPIError) as caught:
            await client.get(API)
    assert caught.value.code == "UNAUTHENTICATED"
    assert len(calls) == 2
    assert credentials.refreshes == 1


async def test_redirect_is_not_followed_with_credentials():
    requests = []
    client, http, _ = client_for(
        lambda request: (
            requests.append(request)
            or httpx.Response(302, headers={"Location": "https://evil.test/"})
        )
    )
    async with http:
        with pytest.raises(CloudAPIError):
            await client.get(API)
    assert len(requests) == 1


@pytest.mark.parametrize("body", [b"[1,2,3]", b"not-json", b"null"])
async def test_invalid_response_shape_has_sanitized_error(body):
    client, http, _ = client_for(lambda request: httpx.Response(200, content=body))
    async with http:
        with pytest.raises(CloudAPIError) as caught:
            await client.get(API)
    assert caught.value.code == "INVALID_RESPONSE"
    assert body.decode() not in str(caught.value)


async def test_response_byte_budget_is_enforced():
    payload = json.dumps({"value": "x" * 100001})
    client, http, _ = client_for(
        lambda request: httpx.Response(200, content=payload), max_api_response_bytes=100000
    )
    async with http:
        with pytest.raises(CloudAPIError) as caught:
            await client.get(API)
    assert caught.value.code == "RESPONSE_TOO_LARGE"


async def test_shared_concurrency_budget_limits_simultaneous_calls():
    active = 0
    peak = 0

    async def handler(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return httpx.Response(200, json={})

    client, http, _ = client_for(handler, max_concurrency=2, per_api_concurrency=1)
    async with http:
        await asyncio.gather(*(client.get(API) for _ in range(8)))
    assert peak == 1


async def test_network_exception_does_not_echo_transport_details():
    def handler(request):
        raise httpx.ConnectError("SECRET CONNECTION DETAILS", request=request)

    client, http, _ = client_for(handler)
    async with http:
        with pytest.raises(CloudAPIError) as caught:
            await client.get(API)
    assert caught.value.code == "UNAVAILABLE"
    assert "SECRET" not in str(caught.value)
