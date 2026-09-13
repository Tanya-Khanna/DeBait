import json
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path

from debait.episodes.models import Edge, Event


class EpisodeStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(Path(__file__).with_name("schema.sql").read_text())

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, event: Event) -> bool:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT * FROM events WHERE provider=? AND provider_event_id=?",
                (event.provider, event.provider_event_id),
            ).fetchone()
            if old:
                if old["episode_id"] != event.episode_id or json.loads(old["payload"]) != event.payload:
                    raise ValueError("Provider event identity conflict")
                return False
            db.execute(
                "INSERT OR IGNORE INTO episodes(id,created_at) VALUES(?,?)",
                (event.episode_id, event.received_at.isoformat()),
            )
            db.execute(
                "INSERT INTO events(event_id,provider,provider_event_id,episode_id,observed_at,received_at,payload) VALUES(?,?,?,?,?,?,?)",
                (
                    event.event_id,
                    event.provider,
                    event.provider_event_id,
                    event.episode_id,
                    event.observed_at.isoformat(),
                    event.received_at.isoformat(),
                    json.dumps(event.payload),
                ),
            )
            return True

    def events(self, episode_id: str) -> list[Event]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM events WHERE episode_id=? ORDER BY seq", (episode_id,)
            ).fetchall()
        return [
            Event(
                **{
                    k: r[k]
                    for k in [
                        "event_id",
                        "provider",
                        "provider_event_id",
                        "episode_id",
                        "observed_at",
                        "received_at",
                    ]
                },
                payload=json.loads(r["payload"]),
            )
            for r in rows
        ]

    def event_feed_after(self, episode_id: str, after_sequence: int, limit: int = 512) -> list[dict]:
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("Event sequence must be a nonnegative integer")
        if type(limit) is not int or not 1 <= limit <= 512:
            raise ValueError("Event feed limit must be between 1 and 512")
        with self.connection() as db:
            rows = db.execute(
                "SELECT seq,event_id,provider,provider_event_id,episode_id,observed_at,received_at,payload "
                "FROM events WHERE episode_id=? AND seq>? ORDER BY seq LIMIT ?",
                (episode_id, after_sequence, limit),
            ).fetchall()
        return [
            {
                "sequence": row["seq"],
                "event_id": row["event_id"],
                "provider": row["provider"],
                "provider_event_id": row["provider_event_id"],
                "episode_id": row["episode_id"],
                "observed_at": row["observed_at"],
                "received_at": row["received_at"],
                "payload": json.loads(row["payload"]),
            }
            for row in rows
        ]

    def add_edge(self, edge: Edge) -> None:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            ids = {edge.source_id, edge.target_id, *edge.provenance_event_ids}
            rows = db.execute(
                f"SELECT event_id,episode_id FROM events WHERE event_id IN ({','.join('?' for _ in ids)})",
                tuple(ids),
            ).fetchall()
            if len(rows) != len(ids) or len({r["episode_id"] for r in rows}) != 1:
                raise ValueError("Edge and provenance must reference existing events in the same episode")
            episode = rows[0]["episode_id"]
            existing = db.execute(
                "SELECT * FROM edges WHERE source_id=? AND target_id=? AND kind=?",
                (edge.source_id, edge.target_id, edge.kind),
            ).fetchone()
            if existing:
                if (
                    existing["confidence"] != edge.confidence
                    or json.loads(existing["provenance"]) != edge.provenance_event_ids
                ):
                    raise ValueError("Existing edge is immutable; append corrected evidence instead")
                return
            db.execute(
                "INSERT INTO edges VALUES(?,?,?,?,?,?)",
                (
                    episode,
                    edge.source_id,
                    edge.target_id,
                    edge.kind,
                    edge.confidence,
                    json.dumps(edge.provenance_event_ids),
                ),
            )

    def edges(self, episode_id: str) -> list[Edge]:
        with self.connection() as db:
            rows = db.execute("SELECT * FROM edges WHERE episode_id=?", (episode_id,)).fetchall()
        return [
            Edge(
                source_id=r["source_id"],
                target_id=r["target_id"],
                kind=r["kind"],
                confidence=r["confidence"],
                provenance_event_ids=json.loads(r["provenance"]),
            )
            for r in rows
        ]

    def summaries(self) -> list[dict]:
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT * FROM episodes ORDER BY created_at DESC")]

    def episode_snapshot(self, episode_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM episodes WHERE id=?", (episode_id,)).fetchone()
        if row is None:
            return None
        return {
            **dict(row),
            "events": [e.model_dump(mode="json") for e in self.events(episode_id)],
            "edges": [e.model_dump() for e in self.edges(episode_id)],
            "agent_trace": self.agent_trace(episode_id),
        }

    def record_agent_step(self, episode_id: str, step: dict) -> None:
        with self.connection() as db:
            db.execute(
                "INSERT OR IGNORE INTO agent_steps(episode_id,step_index,phase,summary,data,created_at) VALUES(?,?,?,?,?,?)",
                (
                    episode_id,
                    step["index"],
                    step["phase"],
                    step["summary"],
                    json.dumps(step.get("data", {})),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def agent_trace(self, episode_id: str) -> list[dict]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT step_index,phase,summary,data FROM agent_steps WHERE episode_id=? ORDER BY step_index",
                (episode_id,),
            ).fetchall()
        return [
            {
                "index": r["step_index"],
                "phase": r["phase"],
                "summary": r["summary"],
                "data": json.loads(r["data"]),
            }
            for r in rows
        ]

    def set_budget_limit(self, limit_microdollars: int) -> None:
        if type(limit_microdollars) is not int or limit_microdollars < 0:
            raise ValueError("Nonnegative integer budget required")
        with self.connection() as db:
            db.execute("UPDATE budget_config SET limit_microdollars=? WHERE id=1", (limit_microdollars,))

    def cached_extraction(self, cache_key: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT body FROM extraction_cache WHERE cache_key=?", (cache_key,)).fetchone()
        return json.loads(row["body"]) if row else None

    def cache_extraction(
        self,
        *,
        cache_key: str,
        episode_id: str,
        evidence_hash: str,
        model: str,
        prompt_version: str,
        body: dict,
    ) -> None:
        serialized = json.dumps(body, sort_keys=True, separators=(",", ":"))
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT episode_id,evidence_hash,model,prompt_version,body "
                "FROM extraction_cache WHERE cache_key=?",
                (cache_key,),
            ).fetchone()
            if old:
                if (
                    old["episode_id"] != episode_id
                    or old["evidence_hash"] != evidence_hash
                    or old["model"] != model
                    or old["prompt_version"] != prompt_version
                ):
                    raise ValueError("Extraction cache identity conflict")
                return
            db.execute(
                "INSERT INTO extraction_cache(cache_key,episode_id,evidence_hash,model,prompt_version,body,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    cache_key,
                    episode_id,
                    evidence_hash,
                    model,
                    prompt_version,
                    serialized,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def bind_resource(self, episode_id, target, account_id: str, evidence_ids: list[str]) -> None:
        # Called only by trusted driver/ingestion instrumentation, never from model text.
        if not evidence_ids:
            raise ValueError("Binding requires source evidence")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                f"SELECT * FROM events WHERE event_id IN ({','.join('?' for _ in evidence_ids)})",
                tuple(evidence_ids),
            ).fetchall()
            if len(rows) != len(set(evidence_ids)) or any(r["episode_id"] != episode_id for r in rows):
                raise ValueError("Binding evidence must belong to this episode")
            if not any(
                json.loads(r["payload"]).get("resource_id") == target.resource_id
                and json.loads(r["payload"]).get("account_id") == account_id
                for r in rows
            ):
                raise ValueError("Evidence does not identify this resource and account")
            old = db.execute(
                "SELECT * FROM bindings WHERE episode_id=? AND provider=? AND resource_id=? AND operation=?",
                (episode_id, target.provider, target.resource_id, target.operation),
            ).fetchone()
            if old:
                if old["account_id"] != account_id or json.loads(old["evidence_ids"]) != evidence_ids:
                    raise ValueError("Binding is immutable")
                return
            db.execute(
                "INSERT INTO bindings VALUES(?,?,?,?,?,?)",
                (
                    episode_id,
                    target.provider,
                    target.resource_id,
                    account_id,
                    target.operation,
                    json.dumps(evidence_ids),
                ),
            )

    def binding(self, episode_id, target):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM bindings WHERE episode_id=? AND provider=? AND resource_id=? AND operation=?",
                (episode_id, target.provider, target.resource_id, target.operation),
            ).fetchone()
            return dict(row) if row else None

    def episode_for_resource(self, provider: str, resource_id: str) -> str | None:
        with self.connection() as db:
            rows = db.execute(
                "SELECT DISTINCT episode_id FROM bindings WHERE provider=? AND resource_id=?",
                (provider, resource_id),
            ).fetchall()
        if len(rows) > 1:
            raise ValueError("Resource is bound to multiple episodes")
        return rows[0]["episode_id"] if rows else None

    def save_consent(self, consent):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO consent_history(episode_id,kind,scope,expires_at,created_at) VALUES(?,'grant',?,?,?)",
                (
                    consent.episode_id,
                    json.dumps(sorted(consent.scope)),
                    consent.expires_at.isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            db.execute(
                "INSERT OR REPLACE INTO consents VALUES(?,?,?,?,?)",
                (
                    consent.episode_id,
                    consent.episode_id,
                    json.dumps(sorted(consent.scope)),
                    consent.expires_at.isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def consent(self, episode_id):
        from debait.episodes.consent import Consent

        with self.connection() as db:
            row = db.execute("SELECT * FROM consents WHERE episode_id=?", (episode_id,)).fetchone()
        return (
            Consent(
                episode_id=episode_id,
                scope=frozenset(tuple(x) for x in json.loads(row["scope"])),
                expires_at=row["expires_at"],
            )
            if row
            else None
        )

    def revoke_consent(self, episode_id):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM consents WHERE episode_id=?", (episode_id,)).fetchone()
            if old:
                db.execute(
                    "INSERT INTO consent_history(episode_id,kind,scope,expires_at,created_at) VALUES(?,'revoke',?,?,?)",
                    (episode_id, old["scope"], old["expires_at"], datetime.now(timezone.utc).isoformat()),
                )
            db.execute("DELETE FROM consents WHERE episode_id=?", (episode_id,))

    def set_state(self, episode_id, state):
        states = {
            "OBSERVING",
            "SUSPICIOUS",
            "HIGH_RISK",
            "REVIEW_REQUIRED",
            "CONTAINING",
            "PARTIALLY_CONTAINED",
            "CONTAINED",
            "PREVENTION_FAILED",
            "LEARNING",
        }
        if state not in states:
            raise ValueError("Unknown episode state")
        with self.connection() as db:
            db.execute("UPDATE episodes SET state=? WHERE id=?", (state, episode_id))

    def persist_action(self, action, *, connection=None):
        from debait.protection.broker import Action

        with nullcontext(connection) if connection is not None else self.connection() as db:
            if not db.in_transaction:
                db.execute("BEGIN IMMEDIATE")
            same_id = db.execute("SELECT body FROM actions WHERE action_id=?", (action.action_id,)).fetchone()
            if same_id and json.loads(same_id["body"]) != action.model_dump():
                raise ValueError("Action ID conflict")
            old = db.execute(
                "SELECT body FROM actions WHERE episode_id=? AND provider=? AND resource_id=? AND operation=? AND policy_version=?",
                (
                    action.episode_id,
                    action.target.provider,
                    action.target.resource_id,
                    action.target.operation,
                    action.policy_version,
                ),
            ).fetchone()
            if old:
                return Action.model_validate_json(old["body"])
            db.execute(
                "INSERT INTO actions(action_id,episode_id,provider,resource_id,operation,policy_version,body) VALUES(?,?,?,?,?,?,?)",
                (
                    action.action_id,
                    action.episode_id,
                    action.target.provider,
                    action.target.resource_id,
                    action.target.operation,
                    action.policy_version,
                    action.model_dump_json(),
                ),
            )
            return action

    def record_attempt(self, action_id, body, request_id=None):
        with self.connection() as db:
            db.execute(
                "INSERT INTO attempts(action_id,request_id,body,created_at) VALUES(?,?,?,?)",
                (action_id, request_id, json.dumps(body), datetime.now(timezone.utc).isoformat()),
            )

    def record_observation(self, action_id, observation):
        with self.connection() as db:
            db.execute(
                "INSERT INTO observations(action_id,body,created_at) VALUES(?,?,?)",
                (action_id, observation.model_dump_json(), datetime.now(timezone.utc).isoformat()),
            )

    def action_history(self, episode_id):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM actions WHERE episode_id=?", (episode_id,)).fetchall()
            result = []
            for row in rows:
                result.append(
                    {
                        **json.loads(row["body"]),
                        "observations": [
                            json.loads(x["body"])
                            for x in db.execute(
                                "SELECT body FROM observations WHERE action_id=? ORDER BY id",
                                (row["action_id"],),
                            )
                        ],
                        "attempts": [
                            json.loads(x["body"])
                            for x in db.execute(
                                "SELECT body FROM attempts WHERE action_id=? ORDER BY id", (row["action_id"],)
                            )
                        ],
                    }
                )
            return result

    def consent_history(self, episode_id):
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM consent_history WHERE episode_id=? ORDER BY sequence", (episode_id,)
            ).fetchall()
        return [{**dict(r), "scope": json.loads(r["scope"])} for r in rows]
