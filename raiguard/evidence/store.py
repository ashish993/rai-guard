"""
Evidence store — async SQLite-backed audit log for all AI interactions.

Every request processed by rai-guard is persisted here with:
- Full check results (scores, patterns matched)
- Compliance mapping snapshots
- Timestamps and session IDs
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import aiosqlite
    _AIOSQLITE_AVAILABLE = True
except ImportError:
    _AIOSQLITE_AVAILABLE = False

from raiguard.checks.base import CheckResult

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS evidence (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    direction   TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    passed      INTEGER NOT NULL,
    checks_json TEXT NOT NULL,
    owasp_json  TEXT,
    eu_ai_json  TEXT,
    meta_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_session ON evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_timestamp ON evidence(timestamp);
CREATE INDEX IF NOT EXISTS idx_passed ON evidence(passed);
"""
# direction column values: 'input' or 'output'


class EvidenceStore:
    """Async SQLite evidence store for compliance audit trails."""

    def __init__(self, db_path: str | Path = "raiguard_audit.db") -> None:
        if not _AIOSQLITE_AVAILABLE:
            raise RuntimeError(
                "aiosqlite is required for the evidence store. "
                "Install with: pip install raiguard[evidence]"
            )
        self.db_path = str(db_path)
        self._db: "aiosqlite.Connection | None" = None

    async def __aenter__(self) -> "EvidenceStore":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        # Enable WAL mode for safe concurrent reads alongside writes
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.executescript(_CREATE_TABLE)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def record(
        self,
        check_results: list[CheckResult],
        direction: str = "input",
        session_id: str | None = None,
        owasp_findings: list[Any] | None = None,
        eu_findings: list[Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> str:
        """Record an AI interaction and its check results. Returns the evidence ID."""
        if not self._db:
            raise RuntimeError("EvidenceStore not connected. Use 'async with EvidenceStore() as store:'")

        if direction not in ("input", "output"):
            raise ValueError(f"direction must be 'input' or 'output', got: {direction!r}")

        evidence_id = str(uuid.uuid4())
        session_id = session_id or str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        risk_score = max((r.score for r in check_results), default=0.0)
        passed = all(r.passed for r in check_results)

        checks_json = json.dumps([
            {
                "check_name": r.check_name,
                "passed": r.passed,
                "severity": r.severity.value,
                "score": r.score,
                "details": r.details,
                "matched_patterns": r.matched_patterns,
                "owasp_refs": r.owasp_refs,
                "eu_ai_act_refs": r.eu_ai_act_refs,
                "remediation": r.remediation,
            }
            for r in check_results
        ])

        owasp_json = None
        if owasp_findings:
            owasp_json = json.dumps([
                {
                    "category_id": f.category_id,
                    "category_name": f.category_name,
                    "risk_score": f.risk_score,
                    "compliant": f.compliant,
                }
                for f in owasp_findings
            ])

        eu_json = None
        if eu_findings:
            eu_json = json.dumps([
                {
                    "article": f.article,
                    "title": f.title,
                    "compliant": f.compliant,
                    "compliance_score": f.compliance_score,
                    "risk_level": f.risk_level,
                }
                for f in eu_findings
            ])

        await self._db.execute(
            """
            INSERT INTO evidence
            (id, session_id, timestamp, direction, risk_score, passed,
             checks_json, owasp_json, eu_ai_json, meta_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id, session_id, timestamp, direction,
                risk_score, int(passed),
                checks_json, owasp_json, eu_json,
                json.dumps(meta or {}),
            ),
        )
        await self._db.commit()
        return evidence_id

    async def query(
        self,
        session_id: str | None = None,
        limit: int = 100,
        failed_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Query evidence records."""
        if not self._db:
            raise RuntimeError("EvidenceStore not connected.")

        # Clamp to prevent unbounded table scans (SQLite treats LIMIT -1 as no limit)
        limit = max(1, min(limit, 10_000))

        conditions = []
        params: list[Any] = []

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if failed_only:
            conditions.append("passed = 0")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.append(limit)

        async with self._db.execute(
            f"SELECT * FROM evidence {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ) as cursor:
            rows = await cursor.fetchall()

        results = []
        for row in rows:
            record = dict(row)
            record["checks"] = json.loads(record.pop("checks_json"))
            record["owasp"] = json.loads(record["owasp_json"]) if record["owasp_json"] else []
            record["eu_ai"] = json.loads(record["eu_ai_json"]) if record["eu_ai_json"] else []
            record["meta"] = json.loads(record["meta_json"]) if record["meta_json"] else {}
            del record["owasp_json"]
            del record["eu_ai_json"]
            del record["meta_json"]
            results.append(record)

        return results

    async def stats(self) -> dict[str, Any]:
        """Aggregate statistics for the dashboard."""
        if not self._db:
            raise RuntimeError("EvidenceStore not connected.")

        async with self._db.execute("SELECT COUNT(*) as total, SUM(CASE WHEN passed=0 THEN 1 ELSE 0 END) as failed, AVG(risk_score) as avg_risk FROM evidence") as cur:
            row = await cur.fetchone()

        total = row["total"] or 0
        failed = row["failed"] or 0
        avg_risk = row["avg_risk"] or 0.0

        return {
            "total_requests": total,
            "blocked_requests": failed,
            "pass_rate": round((total - failed) / total * 100, 1) if total else 100.0,
            "average_risk_score": round(avg_risk, 3),
        }
