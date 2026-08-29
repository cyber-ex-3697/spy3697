"""Evidence store: every tool invocation and its raw output is persisted here
with a stable evidence_id. The LLM is only allowed to reason about, and cite,
records that exist in this store — it never gets to assert a result that
wasn't actually captured from a tool run.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    target TEXT NOT NULL,
    stage TEXT NOT NULL,           -- recon | identify | verify | exec | pcap
    tool TEXT NOT NULL,            -- nmap, nuclei, sqlmap, http, shell, tshark, ...
    command TEXT,                  -- exact command/request that produced this evidence
    raw_output TEXT NOT NULL,
    output_sha256 TEXT NOT NULL,
    exit_code INTEGER,
    started_at REAL NOT NULL,
    finished_at REAL,
    tags TEXT                      -- JSON list, e.g. ["port-scan","web"]
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,        -- info | low | medium | high | critical
    status TEXT NOT NULL,          -- candidate | verified | rejected
    description TEXT,
    evidence_ids TEXT NOT NULL,    -- JSON list of evidence.id this finding is grounded in
    poc_command TEXT,              -- exact reproduction command, filled on verification
    confidence INTEGER,            -- 0-100, computed from evidence count + tool corroboration
                                     -- + independent double-check agreement; null until scored
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS unverified_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    claim_text TEXT NOT NULL,
    reason TEXT NOT NULL,          -- why it was rejected, e.g. "no evidence_id cited"
    created_at REAL NOT NULL
);
"""


@dataclass
class EvidenceRecord:
    id: int
    run_id: str
    target: str
    stage: str
    tool: str
    command: Optional[str]
    raw_output: str
    output_sha256: str
    exit_code: Optional[int]
    started_at: float
    finished_at: Optional[float]
    tags: list[str]


class EvidenceStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate_add_confidence_column()

    def _migrate_add_confidence_column(self) -> None:
        """Older evidence.sqlite files (created before confidence scoring was
        added) won't have this column since CREATE TABLE IF NOT EXISTS skips
        already-existing tables. Add it if missing so old workspaces keep
        working without deleting their history."""
        cols = [row[1] for row in self.conn.execute("PRAGMA table_info(findings)").fetchall()]
        if "confidence" not in cols:
            self.conn.execute("ALTER TABLE findings ADD COLUMN confidence INTEGER")
            self.conn.commit()

    def add_evidence(
        self,
        run_id: str,
        target: str,
        stage: str,
        tool: str,
        raw_output: str,
        command: str | None = None,
        exit_code: int | None = None,
        started_at: float | None = None,
        finished_at: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        started_at = started_at or time.time()
        finished_at = finished_at or time.time()
        output_hash = hashlib.sha256(raw_output.encode("utf-8", errors="replace")).hexdigest()
        cur = self.conn.execute(
            """INSERT INTO evidence
               (run_id, target, stage, tool, command, raw_output, output_sha256,
                exit_code, started_at, finished_at, tags)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run_id, target, stage, tool, command, raw_output, output_hash,
                exit_code, started_at, finished_at, json.dumps(tags or []),
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_evidence(self, evidence_id: int) -> Optional[EvidenceRecord]:
        row = self.conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            return None
        cols = [d[0] for d in self.conn.execute("SELECT * FROM evidence LIMIT 0").description]
        d = dict(zip(cols, row))
        d["tags"] = json.loads(d["tags"] or "[]")
        return EvidenceRecord(**d)

    def evidence_exists(self, evidence_ids: list[int]) -> bool:
        if not evidence_ids:
            return False
        placeholders = ",".join("?" * len(evidence_ids))
        rows = self.conn.execute(
            f"SELECT id FROM evidence WHERE id IN ({placeholders})", evidence_ids
        ).fetchall()
        return len(rows) == len(set(evidence_ids))

    def list_evidence(self, run_id: str, stage: str | None = None) -> list[EvidenceRecord]:
        if stage:
            rows = self.conn.execute(
                "SELECT * FROM evidence WHERE run_id=? AND stage=? ORDER BY id", (run_id, stage)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM evidence WHERE run_id=? ORDER BY id", (run_id,)
            ).fetchall()
        cols = [d[0] for d in self.conn.execute("SELECT * FROM evidence LIMIT 0").description]
        out = []
        for row in rows:
            d = dict(zip(cols, row))
            d["tags"] = json.loads(d["tags"] or "[]")
            out.append(EvidenceRecord(**d))
        return out

    def add_finding(
        self,
        run_id: str,
        target: str,
        title: str,
        severity: str,
        status: str,
        evidence_ids: list[int],
        description: str = "",
        poc_command: str | None = None,
    ) -> int:
        """Findings MUST cite evidence_ids that already exist in the store.
        This is enforced here, not left to the LLM's discretion."""
        if status in ("candidate", "verified") and not self.evidence_exists(evidence_ids):
            raise ValueError(
                f"Refusing to store finding '{title}': one or more evidence_ids {evidence_ids} "
                f"do not exist in the evidence store. Findings must be grounded in captured "
                f"tool output."
            )
        cur = self.conn.execute(
            """INSERT INTO findings
               (run_id, target, title, severity, status, description, evidence_ids,
                poc_command, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                run_id, target, title, severity, status, description,
                json.dumps(evidence_ids), poc_command, time.time(),
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_finding_status(self, finding_id: int, status: str, poc_command: str | None = None):
        if poc_command is not None:
            self.conn.execute(
                "UPDATE findings SET status=?, poc_command=? WHERE id=?",
                (status, poc_command, finding_id),
            )
        else:
            self.conn.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        self.conn.commit()

    def set_finding_confidence(self, finding_id: int, confidence: int) -> None:
        """confidence is 0-100. See orchestrator.compute_confidence() for how
        it's derived -- this method just persists the already-computed value."""
        confidence = max(0, min(100, int(confidence)))
        self.conn.execute(
            "UPDATE findings SET confidence=? WHERE id=?", (confidence, finding_id)
        )
        self.conn.commit()

    def list_findings(self, run_id: str, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE run_id=? AND status=? ORDER BY id",
                (run_id, status),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE run_id=? ORDER BY id", (run_id,)
            ).fetchall()
        cols = [d[0] for d in self.conn.execute("SELECT * FROM findings LIMIT 0").description]
        out = []
        for row in rows:
            d = dict(zip(cols, row))
            d["evidence_ids"] = json.loads(d["evidence_ids"])
            out.append(d)
        return out

    def log_unverified_claim(self, run_id: str, claim_text: str, reason: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO unverified_claims (run_id, claim_text, reason, created_at) VALUES (?,?,?,?)",
            (run_id, claim_text, reason, time.time()),
        )
        self.conn.commit()
        return cur.lastrowid
