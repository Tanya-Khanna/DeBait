"""Durable single-action leases; provider writes still require idempotency and read-back."""

import json

from debait.episodes.store import EpisodeStore
from debait.protection.broker import Action


class ActionQueue:
    def __init__(self, store: EpisodeStore):
        self.store = store
        with store.connection() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS action_jobs(
                action_id TEXT PRIMARY KEY REFERENCES actions(action_id),
                status TEXT NOT NULL DEFAULT 'pending',due_at REAL NOT NULL,
                owner TEXT,lease_until REAL,attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT);
                CREATE INDEX IF NOT EXISTS action_jobs_due ON action_jobs(status,due_at);""")

    def enqueue(self, action: Action, *, now: float) -> str:
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            action = self.store.persist_action(action, connection=db)
            db.execute(
                "INSERT OR IGNORE INTO action_jobs(action_id,due_at) VALUES(?,?)", (action.action_id, now)
            )
        return action.action_id

    def claim(self, owner: str, *, now: float, lease_seconds: float = 30) -> dict | None:
        if not owner or lease_seconds <= 0:
            raise ValueError("Owner and positive lease required")
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT j.*,a.body FROM action_jobs j JOIN actions a USING(action_id)
                WHERE (j.status IN ('pending','retry') AND j.due_at<=?)
                   OR (j.status='running' AND j.lease_until<=?)
                ORDER BY CASE WHEN a.provider='stripe' THEN 0 ELSE 1 END,j.due_at,a.action_id LIMIT 1""",
                (now, now),
            ).fetchone()
            if not row:
                return None
            db.execute(
                "UPDATE action_jobs SET status='running',owner=?,lease_until=?,attempts=attempts+1 WHERE action_id=?",
                (owner, now + lease_seconds, row["action_id"]),
            )
            return {
                **dict(row),
                "owner": owner,
                "attempts": row["attempts"] + 1,
                "action": json.loads(row["body"]),
            }

    def owns(self, action_id: str, owner: str, *, now: float) -> bool:
        with self.store.connection() as db:
            return (
                db.execute(
                    "SELECT 1 FROM action_jobs WHERE action_id=? AND owner=? AND status='running' AND lease_until>?",
                    (action_id, owner, now),
                ).fetchone()
                is not None
            )

    def finish(
        self,
        action_id: str,
        owner: str,
        status: str,
        *,
        now: float,
        due_at: float | None = None,
        error: str | None = None,
    ) -> bool:
        if status not in {"retry", "verified", "blocked", "prevention_failed", "review_required"}:
            raise ValueError("Unknown queue outcome")
        with self.store.connection() as db:
            cur = db.execute(
                """UPDATE action_jobs SET status=?,due_at=?,owner=NULL,lease_until=NULL,last_error=?
                WHERE action_id=? AND owner=? AND status='running' AND lease_until>?""",
                (status, now if due_at is None else due_at, error, action_id, owner, now),
            )
            return cur.rowcount == 1

    def status(self, action_id: str) -> dict | None:
        with self.store.connection() as db:
            row = db.execute("SELECT * FROM action_jobs WHERE action_id=?", (action_id,)).fetchone()
            return dict(row) if row else None
