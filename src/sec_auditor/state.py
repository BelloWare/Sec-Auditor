"""Single-instance durable scan queue and caller-owned sanitized evidence."""

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def binding_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class StateStore:
    def __init__(
        self, path: Path, *, evidence_ttl: int = 3600, retention: int = 86400, max_pending: int = 20
    ):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink():
            raise ValueError("State database must not be a symlink")
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self.path = path
        self.evidence_ttl = evidence_ttl
        self.retention = retention
        self.max_pending = max_pending
        with self.connection() as connection:
            connection.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, actor TEXT NOT NULL, payload TEXT NOT NULL, expires REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS evidence_owner ON evidence(actor, expires);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, request TEXT NOT NULL,
                    status TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                    lease_until REAL, cancel_requested INTEGER NOT NULL DEFAULT 0,
                    progress TEXT NOT NULL DEFAULT '{}', result TEXT, error TEXT
                );
                CREATE INDEX IF NOT EXISTS job_queue ON jobs(status, created);
            """)
            connection.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES('cursor_secret',?)",
                (os.urandom(32).hex(),),
            )
            self._cursor_key = bytes.fromhex(
                connection.execute(
                    "SELECT value FROM settings WHERE key='cursor_secret'"
                ).fetchone()[0]
            )
        path.chmod(0o600)

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def encode_cursor(self, actor: str, operation: str, binding: Any, state: dict[str, Any]) -> str:
        payload = canonical_json(
            {
                "a": actor,
                "op": operation,
                "b": binding_hash(binding),
                "s": state,
                "exp": int(time.time()) + self.evidence_ttl,
            }
        ).encode()
        body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        signature = hmac.new(self._cursor_key, body.encode(), hashlib.sha256).hexdigest()
        cursor = body + "." + signature
        if len(cursor) > 24_000:
            raise ValueError("Upstream continuation token exceeds the supported cursor size")
        return cursor

    def decode_cursor(
        self, cursor: str, actor: str, operation: str, binding: Any
    ) -> dict[str, Any]:
        if len(cursor) > 24_000:
            raise ValueError("Invalid continuation cursor")
        try:
            body, signature = cursor.rsplit(".", 1)
            expected = hmac.new(self._cursor_key, body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            if (
                payload["a"] != actor
                or payload["op"] != operation
                or payload["b"] != binding_hash(binding)
                or payload["exp"] <= time.time()
                or not isinstance(payload["s"], dict)
            ):
                raise ValueError
            return payload["s"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            raise ValueError(
                "Cursor is invalid, expired, or belongs to a different caller/query"
            ) from exc

    def put_evidence(self, actor: str, items: list[dict[str, Any]]) -> str:
        identifier = uuid.uuid4().hex
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO evidence VALUES(?,?,?,?)",
                (identifier, actor, canonical_json(items), time.time() + self.evidence_ttl),
            )
        return identifier

    def get_evidence(self, actor: str, identifier: str) -> list[dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT payload FROM evidence WHERE id=? AND actor=? AND expires>?",
                (identifier, actor, time.time()),
            ).fetchone()
        if row is None:
            raise ValueError("Evidence not found or expired")
        return json.loads(row[0])

    def enqueue(self, actor: str, request: dict[str, Any]) -> str:
        identifier = uuid.uuid4().hex
        now = time.time()
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            pending = conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')"
            ).fetchone()[0]
            if pending >= self.max_pending:
                raise ValueError(
                    "Assessment queue is full; wait for an existing assessment to finish"
                )
            conn.execute(
                "INSERT INTO jobs(id,actor,request,status,created,updated) VALUES(?,?,?,'queued',?,?)",
                (identifier, actor, canonical_json(request), now, now),
            )
        return identifier

    def claim(self) -> dict[str, Any] | None:
        now = time.time()
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE jobs SET status='queued',lease_until=NULL WHERE status='running' AND lease_until<?",
                (now,),
            )
            conn.execute(
                "UPDATE jobs SET status='cancelled',updated=? WHERE status='queued' AND cancel_requested=1",
                (now,),
            )
            row = conn.execute(
                "SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE jobs SET status='running',updated=?,lease_until=? WHERE id=?",
                (now, now + 120, row["id"]),
            )
            result = dict(row)
            result["request"] = json.loads(result["request"])
            result["status"] = "running"
            return result

    def heartbeat(self, job_id: str, progress: dict[str, Any] | None = None) -> bool:
        now = time.time()
        with self.connection() as conn:
            if progress is None:
                conn.execute(
                    "UPDATE jobs SET updated=?,lease_until=? WHERE id=? AND status='running'",
                    (now, now + 120, job_id),
                )
            else:
                conn.execute(
                    "UPDATE jobs SET updated=?,lease_until=?,progress=? WHERE id=? AND status='running'",
                    (now, now + 120, canonical_json(progress), job_id),
                )
            row = conn.execute("SELECT cancel_requested FROM jobs WHERE id=?", (job_id,)).fetchone()
        return row is None or bool(row[0])

    def finish(
        self,
        job_id: str,
        result: dict[str, Any] | None = None,
        *,
        status: str = "completed",
        error: str | None = None,
    ) -> None:
        if status not in {"completed", "cancelled", "failed"}:
            raise ValueError("Invalid terminal job status")
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT cancel_requested FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is not None and row[0] and status == "completed":
                status = "cancelled"
                if result is not None:
                    result = dict(result, cancelled=True, coverage_complete=False)
            conn.execute(
                "UPDATE jobs SET status=?,updated=?,lease_until=NULL,result=?,error=? WHERE id=? AND status='running'",
                (
                    status,
                    time.time(),
                    canonical_json(result) if result is not None else None,
                    error,
                    job_id,
                ),
            )

    def get_job(self, actor: str, identifier: str) -> dict[str, Any]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE id=? AND actor=?", (identifier, actor)
            ).fetchone()
        if row is None:
            raise ValueError("Assessment not found")
        item = dict(row)
        item.pop("actor")
        item.pop("request")
        item.pop("lease_until")
        item["progress"] = json.loads(item["progress"])
        item["result"] = json.loads(item["result"]) if item["result"] else None
        item["cancel_requested"] = bool(item["cancel_requested"])
        return item

    def cancel(self, actor: str, identifier: str) -> dict[str, Any]:
        with self.connection() as conn:
            cursor = conn.execute(
                "UPDATE jobs SET cancel_requested=1,updated=? WHERE id=? AND actor=? AND status IN ('queued','running')",
                (time.time(), identifier, actor),
            )
            if cursor.rowcount == 0:
                # Same non-enumerating response for missing and other callers' IDs.
                row = conn.execute(
                    "SELECT id FROM jobs WHERE id=? AND actor=?", (identifier, actor)
                ).fetchone()
                if row is None:
                    raise ValueError("Assessment not found")
        return self.get_job(actor, identifier)

    def cleanup(self) -> None:
        with self.connection() as conn:
            conn.execute("DELETE FROM evidence WHERE expires<?", (time.time(),))
            conn.execute(
                "DELETE FROM jobs WHERE status NOT IN ('queued','running') AND updated<?",
                (time.time() - self.retention,),
            )
