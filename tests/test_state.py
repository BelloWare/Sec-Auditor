"""Cursor integrity, owner isolation, durable queue behavior, and file modes."""

import hashlib
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from sec_auditor import state
from sec_auditor.state import StateStore


@pytest.fixture
def clock(monkeypatch):
    value = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(state, "time", SimpleNamespace(time=lambda: value.now))
    return value


@pytest.fixture
def store(tmp_path):
    return StateStore(
        tmp_path / "private" / "state.sqlite3", evidence_ttl=60, retention=3600, max_pending=3
    )


def test_cursor_is_bound_to_caller_operation_and_query(store):
    binding = {"projects": ["prod-a"], "kind": "gcp.compute.instances"}
    cursor = store.encode_cursor("agent-a", "list_resources", binding, {"page_token": "next/+="})
    assert store.decode_cursor(cursor, "agent-a", "list_resources", binding) == {
        "page_token": "next/+="
    }
    for actor, operation, query in [
        ("agent-b", "list_resources", binding),
        ("agent-a", "query_logs", binding),
        ("agent-a", "list_resources", {**binding, "projects": ["prod-b"]}),
    ]:
        with pytest.raises(ValueError, match="Cursor"):
            store.decode_cursor(cursor, actor, operation, query)


def test_cursor_tampering_and_oversize_are_rejected(store):
    binding = {"scope": "prod-a"}
    cursor = store.encode_cursor("a", "op", binding, {})
    body, signature = cursor.split(".")
    tampered = [
        body + "." + ("0" if signature[0] != "0" else "1") + signature[1:],
        ("a" if body[0] != "a" else "b") + body[1:] + "." + signature,
        "not-a-cursor",
        ".",
        "x" * 24001,
    ]
    for candidate in tampered:
        with pytest.raises(ValueError):
            store.decode_cursor(candidate, "a", "op", binding)
    with pytest.raises(ValueError, match="size"):
        store.encode_cursor("a", "op", binding, {"token": "x" * 24000})


def test_cursor_expiry_and_restart_persistence(store, clock):
    cursor = store.encode_cursor("a", "op", {}, {"offset": 4})
    restarted = StateStore(store.path, evidence_ttl=60)
    assert restarted.decode_cursor(cursor, "a", "op", {}) == {"offset": 4}
    clock.now += 61
    with pytest.raises(ValueError, match="expired"):
        restarted.decode_cursor(cursor, "a", "op", {})


def test_evidence_owner_isolation_expiry_and_cleanup(store, clock):
    evidence = [{"name": "vm", "projection": "security", "data": {"privateKey": "[REDACTED]"}}]
    identifier = store.put_evidence("agent-a", evidence)
    assert store.get_evidence("agent-a", identifier) == evidence
    for actor, key in [("agent-b", identifier), ("agent-a", "nonexistent")]:
        with pytest.raises(ValueError, match="Evidence not found or expired"):
            store.get_evidence(actor, key)
    clock.now += 61
    with pytest.raises(ValueError, match="expired"):
        store.get_evidence("agent-a", identifier)
    store.cleanup()
    with store.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 0


def test_job_ownership_prevents_read_and_cancel_enumeration(store):
    identifier = store.enqueue("agent-a", {"projects": ["prod-a"]})
    for actor, key in [("agent-b", identifier), ("agent-a", "nonexistent")]:
        with pytest.raises(ValueError, match="Assessment not found"):
            store.get_job(actor, key)
        with pytest.raises(ValueError, match="Assessment not found"):
            store.cancel(actor, key)
    assert store.get_job("agent-a", identifier)["cancel_requested"] is False
    assert "request" not in store.get_job("agent-a", identifier)
    assert "actor" not in store.get_job("agent-a", identifier)


def test_lease_heartbeat_recovery_and_result_persistence(store, clock):
    identifier = store.enqueue("agent-a", {"check_ids": ["example"]})
    claimed = store.claim()
    assert claimed["id"] == identifier
    assert claimed["actor"] == "agent-a"
    assert claimed["request"] == {"check_ids": ["example"]}
    assert store.get_job("agent-a", identifier)["status"] == "running"
    assert store.claim() is None
    clock.now += 100
    assert store.heartbeat(identifier, {"examined": 3}) is False
    clock.now += 100
    assert store.claim() is None
    clock.now += 21
    recovered = store.claim()
    assert recovered["id"] == identifier
    store.finish(identifier, {"findings": [], "coverage_complete": False})
    result = store.get_job("agent-a", identifier)
    assert result["status"] == "completed"
    assert result["result"]["coverage_complete"] is False
    assert result["progress"] == {"examined": 3}
    assert store.claim() is None
    restarted = StateStore(store.path)
    assert restarted.get_job("agent-a", identifier)["result"] == result["result"]


def test_queued_and_running_cancellation_are_durable(store, clock):
    queued = store.enqueue("a", {})
    assert store.cancel("a", queued)["cancel_requested"] is True
    assert store.claim() is None
    assert store.get_job("a", queued)["status"] == "cancelled"
    running = store.enqueue("a", {})
    assert store.claim()["id"] == running
    store.cancel("a", running)
    assert store.heartbeat(running) is True
    store.finish(running, status="cancelled")
    assert store.get_job("a", running)["status"] == "cancelled"
    # A late completion cannot overwrite an already terminal state.
    store.finish(running, {"unexpected": True})
    assert store.get_job("a", running)["status"] == "cancelled"
    assert store.get_job("a", running)["result"] is None


def test_cancelled_expired_lease_is_not_restarted(store, clock):
    identifier = store.enqueue("a", {})
    store.claim()
    store.cancel("a", identifier)
    clock.now += 121
    assert store.claim() is None
    assert store.get_job("a", identifier)["status"] == "cancelled"


def test_queue_capacity_is_atomic_under_concurrent_enqueue(store):
    def enqueue(index):
        try:
            return store.enqueue(f"agent-{index}", {"index": index})
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(enqueue, range(12)))
    assert sum(identifier is not None for identifier in results) == 3
    with store.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 3


def test_cleanup_keeps_active_jobs_and_removes_old_terminal_jobs(store, clock):
    done = store.enqueue("a", {})
    store.claim()
    store.finish(done, {})
    queued = store.enqueue("a", {})
    clock.now += 3601
    store.cleanup()
    with pytest.raises(ValueError, match="not found"):
        store.get_job("a", done)
    assert store.get_job("a", queued)["status"] == "queued"


def test_database_and_created_directory_have_private_modes(store):
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    with store.connection() as connection:
        connection.execute("INSERT INTO settings(key,value) VALUES('test','value')")
        wal = store.path.with_name(store.path.name + "-wal")
        shm = store.path.with_name(store.path.name + "-shm")
        assert wal.exists()
        for path in (wal, shm):
            if path.exists():
                assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_database_is_private_before_sqlite_writes_any_secret(tmp_path, monkeypatch):
    parent = tmp_path / "existing"
    parent.mkdir(mode=0o755)
    path = parent / "state.sqlite3"
    connect = sqlite3.connect
    observed_modes = []

    def recording_connect(db_path, *args, **kwargs):
        observed_modes.append(stat.S_IMODE(path.stat().st_mode) if path.exists() else None)
        return connect(db_path, *args, **kwargs)

    monkeypatch.setattr(state.sqlite3, "connect", recording_connect)
    StateStore(path)
    assert observed_modes
    assert all(mode == 0o600 for mode in observed_modes)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks are unavailable")
def test_database_path_must_not_follow_a_symlink(tmp_path):
    target = tmp_path / "target.sqlite3"
    connection = sqlite3.connect(target)
    connection.execute("CREATE TABLE sentinel(value TEXT)")
    connection.execute("INSERT INTO sentinel VALUES('untouched')")
    connection.commit()
    connection.close()
    before = hashlib.sha256(target.read_bytes()).digest()
    path = tmp_path / "linked.sqlite3"
    path.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        StateStore(path)
    assert hashlib.sha256(target.read_bytes()).digest() == before
