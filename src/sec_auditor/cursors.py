"""Signed, expiring pagination metadata; no files or collected records are kept."""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def binding_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def validate_actor(actor: str) -> None:
    if (
        not isinstance(actor, str)
        or not actor.strip()
        or len(actor) > 1024
        or any(ord(char) < 32 for char in actor)
    ):
        raise ValueError(
            "actor must be a nonempty authenticated identity of at most 1024 characters"
        )


class CursorCodec:
    """Authenticate continuation metadata without retaining it server-side.

    These tokens are signed, not encrypted. They contain a hashed caller ID,
    query digest, expiry, and native pagination state, never resource records.
    Changing a signing key invalidates existing tokens. An omitted key is random
    for this object; provide the same 32-byte key across replicas when needed.
    """

    def __init__(self, *, key: bytes | None = None, ttl_seconds: int = 3600):
        if key is not None and (not isinstance(key, bytes) or len(key) != 32):
            raise ValueError("Cursor signing key must contain 32 bytes")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1:
            raise ValueError("Cursor lifetime must be a positive integer")
        self._key = key if key is not None else secrets.token_bytes(32)
        self.ttl_seconds = ttl_seconds

    def encode_cursor(self, actor: str, operation: str, binding: Any, state: dict[str, Any]) -> str:
        validate_actor(actor)
        if not isinstance(state, dict):
            raise ValueError("Cursor state must be a mapping")
        payload = canonical_json(
            {
                "v": 1,
                "a": binding_hash(actor),
                "op": operation,
                "b": binding_hash(binding),
                "s": state,
                "exp": int(time.time()) + self.ttl_seconds,
            }
        ).encode()
        body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        signature = hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()
        cursor = body + "." + signature
        if len(cursor) > 24_000:
            raise ValueError("Upstream continuation token exceeds the supported cursor size")
        return cursor

    def decode_cursor(
        self, cursor: str, actor: str, operation: str, binding: Any
    ) -> dict[str, Any]:
        validate_actor(actor)
        if not isinstance(cursor, str) or len(cursor) > 24_000:
            raise ValueError("Invalid continuation cursor")
        try:
            body, signature = cursor.rsplit(".", 1)
            expected = hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            if (
                not isinstance(payload, dict)
                or payload.get("v") != 1
                or payload["a"] != binding_hash(actor)
                or payload["op"] != operation
                or payload["b"] != binding_hash(binding)
                or not isinstance(payload["exp"], int)
                or payload["exp"] <= time.time()
                or not isinstance(payload["s"], dict)
            ):
                raise ValueError
            return payload["s"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, binascii.Error) as exc:
            raise ValueError(
                "Cursor is invalid, expired, or belongs to a different caller/query"
            ) from exc
