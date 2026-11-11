"""Real JWT verification and caller isolation without live issuer requests."""

import hashlib
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from sec_auditor import auth
from sec_auditor.auth import (
    CallerTokenVerifier,
    current_actor,
    static_authenticated_app,
    validate_remote_auth,
)
from sec_auditor.config import Settings

ISSUER = "https://issuer.example.com/"
AUDIENCE = "https://audit.example.com/mcp"
SUBJECT = "security-agent"


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwt_settings():
    return Settings(
        allowed_projects=["prod-a"],
        auth_mode="jwt",
        public_url=AUDIENCE,
        jwt_issuer=ISSUER,
        jwt_audience=AUDIENCE,
        jwks_url=ISSUER + "jwks.json",
        jwt_algorithms=["RS256"],
        allowed_subjects=[SUBJECT],
        required_scopes=["security:read"],
    )


@pytest.fixture
def verifier(jwt_settings, signing_key):
    verifier = CallerTokenVerifier(jwt_settings)
    verifier._jwks = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key=signing_key.public_key())
    )
    return verifier


def claims(**changes):
    now = int(time.time())
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": SUBJECT,
        "iat": now - 1,
        "exp": now + 600,
        "scope": "security:read",
        **changes,
    }


def sign(key, payload=None):
    return jwt.encode(payload or claims(), key, algorithm="RS256", headers={"kid": "test-key"})


async def test_verified_jwt_records_the_configured_identity(verifier, signing_key):
    token = await verifier.verify_token(sign(signing_key))
    assert token is not None
    assert token.subject == SUBJECT
    assert token.client_id == SUBJECT
    assert token.resource == AUDIENCE
    assert token.scopes == ["security:read"]
    assert token.expires_at > time.time()


@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://wrong-issuer.example/"},
        {"aud": "https://other-resource.example/mcp"},
        {"exp": 1},
        {"sub": "unapproved-agent"},
        {"scope": "other:read"},
        {"scope": None},
        {"scope": 42},
        {"scope": ["security:read", 7]},
        {"sub": None},
        {"sub": 42},
        {"nbf": int(time.time()) + 3600},
        {"iat": int(time.time()) + 3600},
    ],
)
async def test_wrong_or_malformed_claims_are_rejected(verifier, signing_key, changes):
    assert await verifier.verify_token(sign(signing_key, claims(**changes))) is None


@pytest.mark.parametrize("field", ["iss", "aud", "sub", "iat", "exp"])
async def test_required_claims_cannot_be_omitted(verifier, signing_key, field):
    payload = claims()
    payload.pop(field)
    assert await verifier.verify_token(sign(signing_key, payload)) is None


@pytest.mark.parametrize(
    "field,value",
    [("exp", None), ("exp", []), ("exp", {}), ("exp", float("inf")), ("iat", []), ("iat", {})],
)
async def test_invalid_numeric_claim_types_fail_closed(verifier, signing_key, field, value):
    assert await verifier.verify_token(sign(signing_key, claims(**{field: value}))) is None


async def test_scp_list_and_audience_list_are_supported(verifier, signing_key):
    payload = claims(aud=["other-audience", AUDIENCE], scp=["security:read", "another:scope"])
    payload.pop("scope")
    token = await verifier.verify_token(sign(signing_key, payload))
    assert token is not None
    assert token.scopes == ["security:read", "another:scope"]


async def test_signature_and_algorithm_confusion_are_rejected(verifier):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(sign(other_key)) is None
    assert (
        await verifier.verify_token(
            jwt.encode(claims(), "shared-test-key-with-at-least-32-bytes", algorithm="HS256")
        )
        is None
    )
    assert await verifier.verify_token(jwt.encode(claims(), "", algorithm="none")) is None
    assert await verifier.verify_token("not.a.jwt") is None
    assert await verifier.verify_token("") is None
    assert await verifier.verify_token("x" * 16385) is None


async def test_issuer_failure_fails_closed(verifier, signing_key):
    def unavailable(_):
        raise OSError("issuer unreachable")

    verifier._jwks = SimpleNamespace(get_signing_key_from_jwt=unavailable)
    assert await verifier.verify_token(sign(signing_key)) is None


def static_settings():
    return Settings(
        allowed_projects=["prod-a"],
        auth_mode="static",
        public_url=AUDIENCE,
        static_tokens={
            "agent-a": hashlib.sha256(b"test-token-a").hexdigest(),
            "agent-b": hashlib.sha256(b"test-token-b").hexdigest().upper(),
        },
    )


async def test_static_digest_auth_assigns_each_token_its_caller():
    verifier = CallerTokenVerifier(static_settings())
    token_a = await verifier.verify_token("test-token-a")
    token_b = await verifier.verify_token("test-token-b")
    assert token_a.subject == "agent-a"
    assert token_b.subject == "agent-b"
    assert await verifier.verify_token("wrong-token") is None
    # A stolen configured hash is not itself an accepted bearer token.
    assert await verifier.verify_token(hashlib.sha256(b"test-token-a").hexdigest()) is None


async def test_static_http_boundary_requires_bearer_and_sets_actor_context():
    async def identity(request):
        return JSONResponse({"actor": current_actor()})

    async def health(request):
        return JSONResponse({"status": "ok"})

    application = Starlette(routes=[Route("/mcp", identity), Route("/healthz", health)])
    application = static_authenticated_app(application, CallerTokenVerifier(static_settings()))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://testserver",
        trust_env=False,
    ) as client:
        assert (await client.get("/mcp")).status_code == 401
        assert (
            await client.get("/mcp", headers={"Authorization": "Bearer wrong"})
        ).status_code == 401
        response = await client.get("/mcp", headers={"Authorization": "Bearer test-token-a"})
        assert response.status_code == 200
        assert response.json() == {"actor": "agent-a"}
        assert (await client.get("/healthz")).status_code == 200


@pytest.mark.parametrize(
    "url",
    [
        "http://audit.example.com/mcp",
        "https://user:pass@audit.example.com/mcp",
        "https://audit.example.com/mcp?token=secret",
        "https://audit.example.com/other",
        "https://audit.example.com/mcp#fragment",
    ],
)
def test_remote_auth_rejects_unsafe_resource_urls(url):
    settings = static_settings().model_copy(update={"public_url": url})
    with pytest.raises(ValueError):
        validate_remote_auth(settings)


def test_authentication_configuration_is_explicit(jwt_settings):
    with pytest.raises(ValueError):
        CallerTokenVerifier(jwt_settings.model_copy(update={"allowed_subjects": []}))
    with pytest.raises(ValueError):
        CallerTokenVerifier(static_settings().model_copy(update={"static_tokens": {}}))
    with pytest.raises(ValidationError):
        Settings(allowed_projects=["prod-a"], jwt_algorithms=["HS256"])
    with pytest.raises(ValidationError):
        Settings(
            allowed_projects=["prod-a"], auth_mode="static", static_tokens={"agent": "raw-token"}
        )


def test_local_actor_fallback_requires_explicit_stdio_mode(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: None)
    with pytest.raises(PermissionError):
        current_actor()
    assert current_actor(allow_local=True) == "local-stdio"
