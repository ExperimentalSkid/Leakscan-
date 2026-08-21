"""SQLite-backed resumable state and observation storage."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import Finding
from .utils.time import utc_now

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    normalized_url TEXT,
    final_url TEXT,
    domain TEXT,
    source TEXT,
    classification TEXT,
    score INTEGER,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_normalized_url ON findings(normalized_url);
CREATE INDEX IF NOT EXISTS idx_findings_final_url ON findings(final_url);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);

CREATE TABLE IF NOT EXISTS url_queue (
    normalized_url TEXT PRIMARY KEY,
    original_url TEXT NOT NULL,
    referrer_url TEXT,
    source TEXT,
    query_text TEXT,
    depth INTEGER NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queue_status_priority ON url_queue(status, priority DESC, depth ASC);

CREATE TABLE IF NOT EXISTS queries (
    provider TEXT NOT NULL,
    query_text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    result_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(provider, query_text)
);

CREATE TABLE IF NOT EXISTS pivots (
    pivot_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_url TEXT,
    confidence TEXT,
    searched INTEGER NOT NULL DEFAULT 0,
    discovered_at TEXT NOT NULL,
    PRIMARY KEY(pivot_type, value)
);

CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    left_url TEXT NOT NULL,
    right_url TEXT NOT NULL,
    relation TEXT NOT NULL,
    evidence TEXT,
    observed_at TEXT NOT NULL,
    UNIQUE(left_url, right_url, relation)
);

CREATE TABLE IF NOT EXISTS domain_observations (
    hostname TEXT PRIMARY KEY,
    parent_domain TEXT,
    ip_addresses_json TEXT,
    asn TEXT,
    tls_json TEXT,
    first_seen TEXT NOT NULL,
    last_checked TEXT NOT NULL,
    status TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS provider_state (
    provider TEXT NOT NULL,
    state_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(provider, state_key)
);
"""


class CaseDatabase:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def record_finding(self, finding: Finding) -> int:
        payload = finding.to_dict()
        cursor = self.connection.execute(
            """INSERT INTO findings
               (observed_at, normalized_url, final_url, domain, source, classification, score, payload_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.timestamp_utc or utc_now(), finding.normalized_url, finding.final_url,
                finding.domain, finding.source, finding.classification, finding.score,
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def iter_findings(self) -> Iterable[Finding]:
        rows = self.connection.execute("SELECT payload_json FROM findings ORDER BY id")
        for row in rows:
            yield Finding.from_dict(json.loads(row["payload_json"]))

    def enqueue_url(
        self,
        original_url: str,
        normalized_url: str,
        referrer_url: str = "",
        source: str = "",
        query: str = "",
        depth: int = 0,
        priority: int = 0,
    ) -> bool:
        if not normalized_url:
            return False
        now = utc_now()
        cursor = self.connection.execute(
            """INSERT OR IGNORE INTO url_queue
               (normalized_url, original_url, referrer_url, source, query_text, depth, priority, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (normalized_url, original_url, referrer_url, source, query, depth, priority, now, now),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def claim_pending(self, limit: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT * FROM url_queue WHERE status='pending'
               ORDER BY priority DESC, depth ASC, created_at ASC LIMIT ?""",
            (limit,),
        ).fetchall()
        if rows:
            now = utc_now()
            self.connection.executemany(
                "UPDATE url_queue SET status='active', attempts=attempts+1, updated_at=? WHERE normalized_url=?",
                [(now, row["normalized_url"]) for row in rows],
            )
            self.connection.commit()
        return [dict(row) for row in rows]

    def mark_url(self, normalized_url: str, status: str, error: str = "") -> None:
        self.connection.execute(
            "UPDATE url_queue SET status=?, last_error=?, updated_at=? WHERE normalized_url=?",
            (status, error, utc_now(), normalized_url),
        )
        self.connection.commit()

    def reset_active(self) -> None:
        self.connection.execute("UPDATE url_queue SET status='pending' WHERE status='active'")
        self.connection.commit()

    def queue_counts(self) -> dict[str, int]:
        rows = self.connection.execute("SELECT status, COUNT(*) AS count FROM url_queue GROUP BY status")
        return {row["status"]: row["count"] for row in rows}

    def visited_count(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM url_queue WHERE status IN ('done', 'failed', 'blocked')"
        ).fetchone()
        return int(row["count"])

    def domain_visit_count(self, hostname: str) -> int:
        pattern = f"%://{hostname}/%"
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM url_queue WHERE normalized_url LIKE ? AND status IN ('done','failed','blocked','active')",
            (pattern,),
        ).fetchone()
        return int(row["count"])

    def add_query(self, provider: str, query: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO queries(provider, query_text, updated_at) VALUES (?, ?, ?)",
            (provider, query, utc_now()),
        )
        self.connection.commit()

    def query_status(self, provider: str, query: str) -> str | None:
        row = self.connection.execute(
            "SELECT status FROM queries WHERE provider=? AND query_text=?", (provider, query)
        ).fetchone()
        return row["status"] if row else None

    def finish_query(self, provider: str, query: str, count: int, error: str = "") -> None:
        status = "failed" if error else "done"
        self.connection.execute(
            """INSERT INTO queries(provider, query_text, status, result_count, last_error, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(provider, query_text) DO UPDATE SET
               status=excluded.status, result_count=excluded.result_count,
               last_error=excluded.last_error, updated_at=excluded.updated_at""",
            (provider, query, status, count, error, utc_now()),
        )
        self.connection.commit()

    def get_provider_state(self, provider: str, state_key: str) -> Any | None:
        row = self.connection.execute(
            "SELECT value_json FROM provider_state WHERE provider=? AND state_key=?",
            (provider, state_key),
        ).fetchone()
        return json.loads(row["value_json"]) if row else None

    def set_provider_state(self, provider: str, state_key: str, value: Any) -> None:
        self.connection.execute(
            """INSERT INTO provider_state(provider, state_key, value_json, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(provider, state_key) DO UPDATE SET
               value_json=excluded.value_json, updated_at=excluded.updated_at""",
            (provider, state_key, json.dumps(value, ensure_ascii=False, sort_keys=True), utc_now()),
        )
        self.connection.commit()

    def clear_provider_state(self, provider: str, state_key: str) -> None:
        self.connection.execute(
            "DELETE FROM provider_state WHERE provider=? AND state_key=?",
            (provider, state_key),
        )
        self.connection.commit()

    def add_pivot(self, pivot_type: str, value: str, source_url: str, confidence: str) -> bool:
        cursor = self.connection.execute(
            """INSERT OR IGNORE INTO pivots
               (pivot_type, value, source_url, confidence, discovered_at) VALUES (?, ?, ?, ?, ?)""",
            (pivot_type, value, source_url, confidence, utc_now()),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def pending_pivots(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM pivots WHERE searched=0 ORDER BY discovered_at")
        return [dict(row) for row in rows]

    def pivot_map(self) -> dict[str, set[str]]:
        output: dict[str, set[str]] = {}
        for row in self.connection.execute("SELECT pivot_type, value FROM pivots"):
            output.setdefault(row["pivot_type"], set()).add(row["value"])
        return output

    def mark_pivot_searched(self, pivot_type: str, value: str) -> None:
        self.connection.execute(
            "UPDATE pivots SET searched=1 WHERE pivot_type=? AND value=?", (pivot_type, value)
        )
        self.connection.commit()

    def add_relationship(self, left_url: str, right_url: str, relation: str, evidence: str = "") -> None:
        if not left_url or not right_url or left_url == right_url:
            return
        self.connection.execute(
            """INSERT OR IGNORE INTO relationships
               (left_url, right_url, relation, evidence, observed_at) VALUES (?, ?, ?, ?, ?)""",
            (left_url, right_url, relation, evidence, utc_now()),
        )
        self.connection.commit()

    def iter_relationships(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM relationships ORDER BY id")]

    def upsert_domain(
        self,
        hostname: str,
        parent_domain: str,
        ip_addresses: list[str],
        status: str,
        error: str = "",
        asn: str = "",
        tls: dict[str, Any] | None = None,
    ) -> None:
        now = utc_now()
        self.connection.execute(
            """INSERT INTO domain_observations
               (hostname, parent_domain, ip_addresses_json, asn, tls_json, first_seen, last_checked, status, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(hostname) DO UPDATE SET
               parent_domain=excluded.parent_domain, ip_addresses_json=excluded.ip_addresses_json,
               asn=excluded.asn, tls_json=excluded.tls_json, last_checked=excluded.last_checked,
               status=excluded.status, error=excluded.error""",
            (hostname, parent_domain, json.dumps(ip_addresses), asn, json.dumps(tls or {}), now, now, status, error),
        )
        self.connection.commit()

    def iter_domains(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM domain_observations ORDER BY hostname")]

    def stats(self) -> dict[str, Any]:
        return {
            "findings": self.connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "queries": self.connection.execute("SELECT COUNT(*) FROM queries").fetchone()[0],
            "pivots": self.connection.execute("SELECT COUNT(*) FROM pivots").fetchone()[0],
            "relationships": self.connection.execute("SELECT COUNT(*) FROM relationships").fetchone()[0],
            "queue": self.queue_counts(),
        }
