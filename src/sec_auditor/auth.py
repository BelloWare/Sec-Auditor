"""MCP caller authentication is independent of Google Application Default Credentials."""

import asyncio
import hashlib
import hmac
import time
from urllib.parse import urlsplit

import jwt
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware, get_access_token
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import JSONResponse

from sec_auditor.config import Settings


def validate_remote_auth(settings: Settings) -> None:
    parsed = urlsplit(settings.public_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "public_url must be an absolute MCP URL without credentials, query, or fragment"
        )
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Remote MCP public_url must use HTTPS")
    if parsed.path.rstrip("/") != "/mcp":
        raise ValueError("public_url must end in /mcp")
    if settings.auth_mode == "static":
        if not settings.static_tokens:
            raise ValueError("Static HTTP authentication requires configured SHA-256 token digests")
        return
    if not settings.allowed_subjects:
        raise ValueError("JWT authentication requires an explicit allowed_subjects list")
    if not settings.jwt_issuer or not settings.jwt_audience or not settings.jwks_url:
        raise ValueError("JWT authentication requires issuer, audience, and JWKS URL")
    for value in (settings.jwt_issuer, settings.jwks_url):
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.fragment
        ):
            raise ValueError("JWT issuer and JWKS endpoints must be configured HTTPS URLs")


class CallerTokenVerifier:
    def __init__(self, settings: Settings):
        validate_remote_auth(settings)
        self.settings = settings
        self._jwks = (
            jwt.PyJWKClient(settings.jwks_url, cache_jwk_set=True, lifespan=300, timeout=5)
            if settings.auth_mode == "jwt"
            else None
        )
        self._verify_slots = asyncio.Semaphore(4)

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token or len(token) > 16_384:
            return None
        if self.settings.auth_mode == "static":
            # Tokens themselves never live in configuration, logs, SQLite, or MCP responses.
            digest = hashlib.sha256(token.encode()).hexdigest()
            subject: str | None = None
            for candidate, configured in self.settings.static_tokens.items():
                if hmac.compare_digest(digest, configured.get_secret_value().lower()):
                    subject = candidate
            if subject is None:
                return None
            return AccessToken(
                token=token,
                client_id=subject,
                subject=subject,
                scopes=self.settings.required_scopes,
                resource=self.settings.public_url,
            )
        async with self._verify_slots:
            try:
                claims = await asyncio.to_thread(self._decode, token)
            except (jwt.PyJWTError, ValueError, TypeError, OverflowError, OSError):
                return None
        subject = claims.get("sub")
        if not isinstance(subject, str) or subject not in self.settings.allowed_subjects:
            return None
        raw_scopes = claims.get("scope", claims.get("scp", []))
        scopes = raw_scopes.split() if isinstance(raw_scopes, str) else raw_scopes
        if not isinstance(scopes, list) or not all(isinstance(x, str) for x in scopes):
            return None
        if not set(self.settings.required_scopes).issubset(scopes):
            return None
        expiry = claims.get("exp")
        if (
            not isinstance(expiry, (int, float))
            or isinstance(expiry, bool)
            or expiry <= time.time()
            or expiry > 253402300799
        ):
            return None
        return AccessToken(
            token=token,
            client_id=subject,
            subject=subject,
            scopes=scopes,
            expires_at=int(expiry),
            resource=self.settings.public_url,
        )

    def _decode(self, token: str) -> dict:
        assert self._jwks is not None
        key = self._jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key.key,
            algorithms=self.settings.jwt_algorithms,
            audience=self.settings.jwt_audience,
            issuer=self.settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )


def current_actor(*, allow_local: bool = False) -> str:
    token = get_access_token()
    if token is not None:
        return token.subject or token.client_id
    if allow_local:
        return "local-stdio"
    raise PermissionError("An authenticated MCP caller is required")


class _RequireStaticCaller:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") not in {"/healthz", "/readyz"}:
            user = scope.get("user")
            if not user or not user.is_authenticated:
                await JSONResponse(
                    {"error": "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )(scope, receive, send)
                return
        await self.app(scope, receive, send)


def static_authenticated_app(app, verifier: CallerTokenVerifier):
    """Preconfigured bearer headers for machine clients; this mode is not an OAuth issuer."""
    return AuthenticationMiddleware(
        AuthContextMiddleware(_RequireStaticCaller(app)), backend=BearerAuthBackend(verifier)
    )
