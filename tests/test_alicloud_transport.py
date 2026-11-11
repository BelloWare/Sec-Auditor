"""Account/region isolation and wire boundaries using real SDK request signing."""

import asyncio
import gzip
import json
import time
import zlib
from types import SimpleNamespace

import httpx
import pytest

from sec_auditor.config import Settings
from sec_auditor.providers.alicloud_catalog import OPERATIONS, AliOperation
from sec_auditor.providers.alicloud_transport import AlibabaRestClient, _xml_body
from sec_auditor.transport import CloudAPIError

ACCOUNT = "1234567890123456"
OTHER = "9876543210987654"
REGION = "cn-hangzhou"


class Credentials:
    def __init__(self):
        self.calls = 0
        self.generation = 1

    async def get_credential_async(self):
        self.calls += 1
        return SimpleNamespace(
            access_key_id=f"test-id-{self.generation}",
            access_key_secret="not-a-real-secret",
            security_token=f"not-a-real-token-{self.generation}",
        )


def settings(**extra):
    return Settings(
        allowed_alicloud_accounts=extra.pop("allowed_alicloud_accounts", [ACCOUNT]),
        allowed_alicloud_regions=extra.pop("allowed_alicloud_regions", [REGION]),
        requests_per_second=100,
        request_retries=0,
        **extra,
    )


def transport(handler, *, config=None, credentials=None):
    return AlibabaRestClient(
        config or settings(),
        credentials=credentials or Credentials(),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False),
    )


def identity_or(request, response):
    if request.headers.get("x-acs-action") == "GetCallerIdentity":
        return httpx.Response(200, json={"AccountId": ACCOUNT, "IdentityType": "AssumedRoleUser"})
    return response


async def test_openapi_uses_real_sdk_signer_and_caches_account_proof():
    seen = []

    def handler(request):
        seen.append(request)
        return identity_or(request, httpx.Response(200, json={"Instances": {"Instance": []}}))

    client = transport(handler)
    for _ in range(2):
        result = await client.execute(
            ACCOUNT,
            "ecs.DescribeInstances",
            region=REGION,
            parameters={"RegionId": REGION, "MaxResults": 10},
        )
        assert result == {"Instances": {"Instance": []}}
    assert [r.headers["x-acs-action"] for r in seen] == [
        "GetCallerIdentity",
        "DescribeInstances",
        "DescribeInstances",
    ]
    assert seen[1].url.host == "ecs.cn-hangzhou.aliyuncs.com"
    assert seen[1].headers["authorization"].startswith("ACS3-HMAC-SHA256 Credential=test-id-1,")
    assert seen[1].headers["x-acs-security-token"] == "not-a-real-token-1"
    assert "not-a-real-secret" not in str(seen[1].headers)
    assert "test-id" not in str(seen[1].url)


@pytest.mark.parametrize(
    "account,region", [(OTHER, REGION), (ACCOUNT, "us-west-1"), (ACCOUNT, None)]
)
async def test_scope_rejected_before_loading_credentials(account, region):
    credentials = Credentials()
    client = transport(
        lambda _: pytest.fail("Network access must not occur"), credentials=credentials
    )
    with pytest.raises((CloudAPIError, ValueError)):
        await client.execute(account, "ecs.DescribeInstances", region=region)
    assert credentials.calls == 0


async def test_identity_mismatch_blocks_target_call_even_if_both_accounts_allowed():
    seen = []

    def handler(request):
        seen.append(request.headers["x-acs-action"])
        return httpx.Response(200, json={"AccountId": OTHER})

    client = transport(handler, config=settings(allowed_alicloud_accounts=[ACCOUNT, OTHER]))
    with pytest.raises(CloudAPIError, match="does not match") as error:
        await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    assert error.value.code == "SCOPE_DENIED"
    assert seen == ["GetCallerIdentity"]


async def test_credential_rotation_requires_new_identity_proof():
    credentials = Credentials()
    actions = []

    def handler(request):
        action = request.headers["x-acs-action"]
        actions.append(action)
        if action == "GetCallerIdentity":
            return httpx.Response(
                200,
                json={
                    "AccountId": ACCOUNT
                    if "test-id-1," in request.headers["authorization"]
                    else OTHER
                },
            )
        return httpx.Response(200, json={})

    client = transport(handler, credentials=credentials)
    await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    credentials.generation = 2
    with pytest.raises(CloudAPIError, match="does not match"):
        await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    assert actions == ["GetCallerIdentity", "DescribeInstances", "GetCallerIdentity"]


async def test_concurrent_reads_share_identity_check():
    actions = []

    async def handler(request):
        actions.append(request.headers["x-acs-action"])
        await asyncio.sleep(0)
        return identity_or(request, httpx.Response(200, json={}))

    client = transport(handler)
    await asyncio.gather(
        *(client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION) for _ in range(6))
    )
    assert actions.count("GetCallerIdentity") == 1
    assert actions.count("DescribeInstances") == 6


@pytest.mark.parametrize("body", [{}, {"AccountId": 123456789}, {"AccountId": "unknown"}])
async def test_invalid_sts_account_fails_closed(body):
    client = transport(lambda _: httpx.Response(200, json=body))
    with pytest.raises(CloudAPIError) as error:
        await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    assert error.value.code == "INVALID_IDENTITY"


@pytest.mark.parametrize(
    "operation,parameters",
    [
        ("ecs.RunCommand", {}),
        ("oss.GetObject", {}),
        ("ecs.DescribeInstances", {"Endpoint": "evil.example"}),
        ("ecs.DescribeInstances", {"RegionId": "us-west-1"}),
        ("ecs.DescribeInstances", {"MaxResults": "10\n"}),
    ],
)
async def test_unknown_or_injected_operations_never_access_network(operation, parameters):
    client = transport(lambda _: pytest.fail("Network access must not occur"))
    with pytest.raises(ValueError):
        await client.execute(ACCOUNT, operation, region=REGION, parameters=parameters)


def test_mutations_and_content_reads_cannot_enter_transport_through_bad_spec():
    for action in [
        "DeleteBucket",
        "GetObject",
        "GetBucket",
        "GetSecretValue",
        "DescribeClusterUserKubeconfig",
        "DescribeUserData",
        "DescribeDBInstanceSSL",
    ]:
        operation = AliOperation("bad", "ecs", "2020-01-01", action, "ecs.cn-hangzhou.aliyuncs.com")
        with pytest.raises(ValueError):
            AlibabaRestClient._validate_operation(operation, {})


def test_compiled_catalog_actions_pass_transport_read_boundary():
    for operation in OPERATIONS.values():
        # All catalog ROA path arguments get a valid inert placeholder.
        params = {key: "c123456" for key in operation.path_parameters}
        AlibabaRestClient._validate_operation(operation, params)


async def test_global_reads_do_not_require_regions_and_metadata_login_is_allowed():
    client = transport(
        lambda r: identity_or(
            r, httpx.Response(200, json={"LoginProfile": {"MFABindRequired": True}})
        ),
        config=settings(allowed_alicloud_regions=[]),
    )
    result = await client.execute(
        ACCOUNT, "ram.GetLoginProfile", parameters={"UserName": "auditor"}
    )
    assert result["LoginProfile"]["MFABindRequired"]


async def test_ack_path_traversal_is_rejected():
    operation = next(op for op in OPERATIONS.values() if op.path_parameters)
    client = transport(lambda _: pytest.fail("Network access must not occur"))
    with pytest.raises(ValueError):
        await client.execute(
            ACCOUNT, operation.id, region=REGION, parameters={"ClusterId": "../credentials"}
        )


@pytest.mark.parametrize(
    "status,code",
    [
        (302, "UPSTREAM_ERROR"),
        (401, "UNAUTHENTICATED"),
        (403, "PERMISSION_DENIED"),
        (404, "NOT_FOUND"),
        (429, "RESOURCE_EXHAUSTED"),
        (503, "UPSTREAM_ERROR"),
    ],
)
async def test_upstream_errors_do_not_leak_payloads_or_follow_redirects(status, code):
    calls = []

    def handler(request):
        calls.append(request)
        return identity_or(
            request,
            httpx.Response(
                status,
                text="not-a-real-secret not-a-real-token",
                headers={"Location": "https://evil.example/"},
            ),
        )

    client = transport(handler)
    with pytest.raises(CloudAPIError) as error:
        await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    assert error.value.code == code
    assert "secret" not in str(error.value)
    assert "token" not in str(error.value)
    assert len(calls) == 2


async def test_response_size_limit_applies_before_json_parse():
    client = transport(
        lambda r: identity_or(r, httpx.Response(200, content=b"x" * 100_001)),
        config=settings(max_api_response_bytes=100_000),
    )
    with pytest.raises(CloudAPIError) as error:
        await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    assert error.value.code == "RESPONSE_TOO_LARGE"


async def test_non_json_response_is_explicit_error():
    client = transport(lambda r: identity_or(r, httpx.Response(200, content=b"<html>")))
    with pytest.raises(CloudAPIError) as error:
        await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    assert error.value.code == "INVALID_RESPONSE"


async def test_credential_provider_errors_are_sanitized():
    class BadCredentials:
        async def get_credential_async(self):
            raise RuntimeError("not-a-real-secret")

    client = transport(
        lambda _: pytest.fail("Network access must not occur"), credentials=BadCredentials()
    )
    with pytest.raises(CloudAPIError) as error:
        await client.execute(ACCOUNT, "ecs.DescribeInstances", region=REGION)
    assert error.value.code == "UNAUTHENTICATED"
    assert "not-a-real" not in str(error.value)


def bucket_info(owner=ACCOUNT, location="oss-cn-hangzhou", name="audit-bucket"):
    return f"<BucketInfo><Bucket><Name>{name}</Name><Location>{location}</Location><Owner><ID>{owner}</ID></Owner><AccessControlList><Grant>private</Grant></AccessControlList></Bucket></BucketInfo>"


async def test_oss_owner_and_region_proved_before_acl_read_and_sdk_signer_used():
    seen = []

    def handler(request):
        seen.append(request)
        if request.headers.get("x-acs-action"):
            return identity_or(request, httpx.Response(500))
        if "bucketInfo" in request.url.params:
            return httpx.Response(200, text=bucket_info())
        assert "acl" in request.url.params
        return httpx.Response(
            200,
            text="<AccessControlPolicy><AccessControlList><Grant>private</Grant></AccessControlList></AccessControlPolicy>",
        )

    client = transport(handler)
    result = await client.execute(
        ACCOUNT, "oss.GetBucketAcl", region=REGION, parameters={"BucketName": "audit-bucket"}
    )
    assert result == {"AccessControlList": {"Grant": "private"}}
    assert len(seen) == 3
    assert seen[-1].url.host == "audit-bucket.oss-cn-hangzhou.aliyuncs.com"
    assert seen[-1].headers["authorization"].startswith("OSS4-HMAC-SHA256 Credential=")
    assert seen[-1].url.path == "/"
    assert "not-a-real-secret" not in str(seen[-1].headers)


@pytest.mark.parametrize(
    "owner,location,name",
    [
        (OTHER, "oss-cn-hangzhou", "audit-bucket"),
        (ACCOUNT, "oss-us-west-1", "audit-bucket"),
        (ACCOUNT, "oss-cn-hangzhou", "other-bucket"),
    ],
)
async def test_oss_wrong_owner_region_or_name_never_reads_configuration(owner, location, name):
    seen = []

    def handler(request):
        seen.append(request)
        return identity_or(request, httpx.Response(200, text=bucket_info(owner, location, name)))

    client = transport(handler)
    with pytest.raises(CloudAPIError) as error:
        await client.execute(
            ACCOUNT, "oss.GetBucketAcl", region=REGION, parameters={"BucketName": "audit-bucket"}
        )
    assert error.value.code == "SCOPE_DENIED"
    assert len(seen) == 2
    assert "bucketInfo" in seen[-1].url.params


async def test_oss_listing_filters_regions_without_losing_continuation():
    body = f"""<ListAllMyBucketsResult><Owner><ID>{ACCOUNT}</ID></Owner><Buckets>
    <Bucket><Name>outside-bucket</Name><Location>oss-us-west-1</Location></Bucket>
    </Buckets><IsTruncated>true</IsTruncated><NextMarker>outside-bucket</NextMarker></ListAllMyBucketsResult>"""
    client = transport(lambda r: identity_or(r, httpx.Response(200, text=body)))
    result = await client.execute(
        ACCOUNT, "oss.ListBuckets", region=REGION, parameters={"MaxKeys": 20}
    )
    assert result == {"Buckets": [], "IsTruncated": True, "NextMarker": "outside-bucket"}


def test_oss_xml_entities_are_rejected():
    with pytest.raises(CloudAPIError):
        _xml_body(b'<!DOCTYPE x [<!ENTITY s SYSTEM "file:///etc/passwd">]><x>&s;</x>')


def sls_settings(**extra):
    return settings(
        alicloud_logstores={
            "flows": {
                "account_id": ACCOUNT,
                "region": REGION,
                "project": "security-audit",
                "logstore": "vpc_flows",
                "category": "vpc_flows",
            }
        },
        **extra,
    )


async def sls_query(client, **extra):
    now = int(time.time()) - 1
    args = dict(
        region=REGION,
        project="security-audit",
        logstore="vpc_flows",
        start_time=now - 3600,
        end_time=now,
        line=2,
    )
    args.update(extra)
    return await client.query_logs(ACCOUNT, **args)


async def test_sls_fixed_query_signing_and_pagination():
    seen = []

    def handler(request):
        seen.append(request)
        return identity_or(
            request,
            httpx.Response(
                200,
                json={
                    "meta": {"progress": "Complete", "hasSQL": False},
                    "data": [{"srcaddr": "10.0.0.1"}, {"srcaddr": "10.0.0.2"}],
                },
            ),
        )

    client = transport(handler, config=sls_settings())
    result = await sls_query(client)
    assert result["next_offset"] == 2
    assert result["progress"] == "Complete"
    request = seen[-1]
    assert request.url.host == "security-audit.cn-hangzhou.log.aliyuncs.com"
    assert request.method == "POST"
    assert request.url.path == "/logstores/vpc_flows/logs"
    assert not request.url.params
    body = json.loads(request.content)
    assert body["query"] == "*"
    assert body["powerSql"] is False
    assert body["line"] == 2
    assert request.headers["accept-encoding"] == "gzip"
    assert request.headers["x-log-bodyrawsize"] == str(len(request.content))
    assert request.headers["Authorization"].startswith("SLS4-HMAC-SHA256 Credential=")


async def test_incomplete_sls_response_retries_same_offset():
    client = transport(
        lambda r: identity_or(
            r,
            httpx.Response(
                200, json={"meta": {"progress": "Incomplete"}, "data": [{"srcaddr": "10.0.0.1"}]}
            ),
        ),
        config=sls_settings(),
    )
    result = await sls_query(client, offset=7)
    assert result["next_offset"] == 7
    assert result["has_more"]


@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress])
async def test_getlogsv2_bounded_gzip_and_zlib_responses(compress):
    body = json.dumps(
        {"meta": {"progress": "Complete", "hasSQL": False}, "data": [{"srcaddr": "10.0.0.1"}]}
    ).encode()
    client = transport(
        lambda r: identity_or(
            r,
            httpx.Response(
                200,
                content=compress(body),
                headers={"x-log-compresstype": "gzip", "x-log-bodyrawsize": str(len(body))},
            ),
        ),
        config=sls_settings(),
    )
    result = await sls_query(client)
    assert result["logs"] == [{"srcaddr": "10.0.0.1"}]
    assert result["next_offset"] is None


async def test_getlogsv2_compression_bomb_cannot_bypass_byte_limit():
    body = zlib.compress(b"x" * 100_001)
    client = transport(
        lambda r: identity_or(
            r,
            httpx.Response(
                200, content=body, headers={"x-log-compresstype": "gzip", "x-log-bodyrawsize": "20"}
            ),
        ),
        config=sls_settings(max_api_response_bytes=100_000),
    )
    with pytest.raises(CloudAPIError) as error:
        await sls_query(client)
    assert error.value.code == "RESPONSE_TOO_LARGE"


@pytest.mark.parametrize(
    "headers,content",
    [
        ({"x-log-compresstype": "lz4"}, b"opaque"),
        ({"x-log-compresstype": "gzip"}, b"not-compressed"),
        ({"x-log-compresstype": "gzip", "x-log-bodyrawsize": "invalid"}, b"opaque"),
        ({}, b'[{"srcaddr":"legacy-array-response"}]'),
        ({}, b'{"meta":{"progress":"Complete","hasSQL":true},"data":[]}'),
    ],
)
async def test_getlogsv2_rejects_bad_compression_and_unexpected_response_shape(headers, content):
    client = transport(
        lambda r: identity_or(r, httpx.Response(200, content=content, headers=headers)),
        config=sls_settings(),
    )
    with pytest.raises(CloudAPIError) as error:
        await sls_query(client)
    assert error.value.code == "INVALID_RESPONSE"


@pytest.mark.parametrize(
    "extra",
    [
        {"query": "* | select password"},
        {"project": "not-registered"},
        {"logstore": "other"},
        {"offset": -1},
        {"offset": 100_001},
        {"line": 101},
        {"start_time": 0},
        {"end_time": 99_999_999_999},
        {"project": "evil.example"},
    ],
)
async def test_sls_scope_sql_and_time_boundaries(extra):
    credentials = Credentials()
    client = transport(
        lambda _: pytest.fail("Network access must not occur"),
        config=sls_settings(),
        credentials=credentials,
    )
    with pytest.raises((ValueError, CloudAPIError)):
        await sls_query(client, **extra)
    assert credentials.calls == 0


@pytest.mark.parametrize(
    "parameters",
    [
        {},
        {"StartTime": "2026-01-01", "EndTime": "2026-01-01"},
        {"StartTime": "2026-01-01T00:00:00Z", "EndTime": "2026-02-01T00:00:00Z"},
    ],
)
async def test_actiontrail_cannot_bypass_log_time_boundaries(parameters):
    client = transport(lambda _: pytest.fail("Network access must not occur"))
    with pytest.raises(ValueError, match="time window"):
        await client.execute(
            ACCOUNT, "actiontrail.LookupEvents", region=REGION, parameters=parameters
        )
