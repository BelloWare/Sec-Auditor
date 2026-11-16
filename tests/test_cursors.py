"""Caller/query binding and stateless key lifetime are explicit security contracts."""

import base64
import json

import pytest

from sec_auditor.cursors import CursorCodec, validate_actor

KEY = b"c" * 32
BINDING = {"provider": "gcp", "project": "project-a", "page_size": 10}


def test_cursor_carries_only_signed_pagination_metadata_and_hashed_actor():
    codec = CursorCodec(key=KEY)
    cursor = codec.encode_cursor("caller-private-name", "read", BINDING, {"token": "native-next"})
    assert codec.decode_cursor(cursor, "caller-private-name", "read", BINDING) == {
        "token": "native-next"
    }
    encoded = cursor.split(".")[0]
    payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert "caller-private-name" not in json.dumps(payload)
    assert payload["s"] == {"token": "native-next"}
    assert not {"items", "records", "data", "evidence"}.intersection(payload)


@pytest.mark.parametrize(
    "actor,operation,binding",
    [
        ("other-caller", "read", BINDING),
        ("caller", "other-tool", BINDING),
        ("caller", "read", dict(BINDING, project="project-b")),
        ("caller", "read", dict(BINDING, provider="alicloud")),
        ("caller", "read", dict(BINDING, page_size=9)),
    ],
)
def test_cursor_cannot_cross_caller_tool_or_native_query(actor, operation, binding):
    codec = CursorCodec(key=KEY)
    cursor = codec.encode_cursor("caller", "read", BINDING, {"token": "next"})
    with pytest.raises(ValueError, match="different caller/query"):
        codec.decode_cursor(cursor, actor, operation, binding)


@pytest.mark.parametrize("cursor", ["", "bad", "bad.signature", "x" * 24001, None, 1])
def test_invalid_cursors_fail_closed(cursor):
    with pytest.raises(ValueError):
        CursorCodec(key=KEY).decode_cursor(cursor, "caller", "read", BINDING)


def test_cursor_tampering_is_rejected():
    codec = CursorCodec(key=KEY)
    cursor = codec.encode_cursor("caller", "read", BINDING, {"token": "next"})
    body, signature = cursor.split(".")
    changed = ("a" if body[0] != "a" else "b") + body[1:]
    with pytest.raises(ValueError):
        codec.decode_cursor(changed + "." + signature, "caller", "read", BINDING)


def test_expiry_uses_configured_lifetime(monkeypatch):
    monkeypatch.setattr("sec_auditor.cursors.time.time", lambda: 1000)
    codec = CursorCodec(key=KEY, ttl_seconds=60)
    cursor = codec.encode_cursor("caller", "read", BINDING, {})
    monkeypatch.setattr("sec_auditor.cursors.time.time", lambda: 1059)
    assert codec.decode_cursor(cursor, "caller", "read", BINDING) == {}
    monkeypatch.setattr("sec_auditor.cursors.time.time", lambda: 1060)
    with pytest.raises(ValueError, match="expired"):
        codec.decode_cursor(cursor, "caller", "read", BINDING)


def test_shared_key_supports_other_workers_and_rotation_invalidates_cursors():
    cursor = CursorCodec(key=KEY).encode_cursor("caller", "read", BINDING, {"token": "next"})
    assert CursorCodec(key=KEY).decode_cursor(cursor, "caller", "read", BINDING)["token"] == "next"
    for codec in (CursorCodec(key=b"d" * 32), CursorCodec()):
        with pytest.raises(ValueError):
            codec.decode_cursor(cursor, "caller", "read", BINDING)


def test_default_key_is_unique_per_connector_instance():
    first, second = CursorCodec(), CursorCodec()
    cursor = first.encode_cursor("caller", "read", BINDING, {})
    with pytest.raises(ValueError):
        second.decode_cursor(cursor, "caller", "read", BINDING)


def test_overlong_native_cursor_is_rejected_without_retaining_it():
    with pytest.raises(ValueError, match="Upstream continuation"):
        CursorCodec(key=KEY).encode_cursor("caller", "read", BINDING, {"token": "n" * 24000})


@pytest.mark.parametrize("actor", ["", " ", "a\n", "x" * 1025, None, False])
def test_empty_or_unbounded_caller_identity_is_rejected(actor):
    with pytest.raises(ValueError):
        validate_actor(actor)
