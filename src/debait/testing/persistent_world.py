"""A separate SQLite-backed synthetic provider world that survives defender process exit."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from debait.providers.base import Observation, ProviderStateChanged, Receipt
from debait.testing.world import FixtureWorld


class PersistentFixtureWorld:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        initial = FixtureWorld()
        with self.connection() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS resources(id TEXT PRIMARY KEY,provider TEXT,state TEXT);
                CREATE TABLE IF NOT EXISTS effects(action_id TEXT PRIMARY KEY,body TEXT NOT NULL,effect_key TEXT NOT NULL);""")
            db.executemany(
                "INSERT OR IGNORE INTO resources VALUES(?,?,?)",
                [(id, initial.providers[id], state) for id, state in initial.states.items()],
            )

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    async def read(self, resource_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
        if row is None:
            raise PermissionError("Resource outside local world")
        level = "acknowledged" if "message" in resource_id and row["state"] == "removed" else "read_back"
        return Observation(
            provider=row["provider"],
            resource_id=resource_id,
            account_id="test",
            state=row["state"],
            level=level,
            observed_at=datetime.now(timezone.utc),
            source="persistent_local_world",
        )

    async def act(self, action):
        transitions = {
            "cancel": ("stripe", {"requires_confirmation", "requires_capture"}, "canceled"),
            "end": ("twilio", {"in-progress"}, "completed"),
            "delete": ("telegram", {"present"}, "removed"),
            "ban": ("telegram", {"member"}, "banned"),
            "release": ("browserbase", {"active"}, "terminated"),
        }
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT body FROM effects WHERE action_id=?", (action.action_id,)).fetchone()
            if old:
                if json.loads(old["body"]) != action.model_dump():
                    raise ValueError("Idempotency key reused with different parameters")
                return Receipt(request_id=action.action_id, acknowledged=True)
            row = db.execute("SELECT * FROM resources WHERE id=?", (action.target.resource_id,)).fetchone()
            if action.target.operation not in transitions or row is None:
                raise PermissionError("Operation outside world")
            provider, eligible, terminal = transitions[action.target.operation]
            if row["provider"] != provider or action.target.provider != provider:
                raise PermissionError("Provider mismatch")
            if row["state"] not in eligible:
                raise ProviderStateChanged("Ineligible provider state")
            db.execute("UPDATE resources SET state=? WHERE id=?", (terminal, action.target.resource_id))
            db.execute(
                "INSERT INTO effects VALUES(?,?,?)",
                (
                    action.action_id,
                    action.model_dump_json(),
                    f"{provider}.{action.target.operation}:{action.target.resource_id}",
                ),
            )
        return Receipt(request_id=action.action_id, acknowledged=True)

    def effect_count(self, key):
        with self.connection() as db:
            return db.execute("SELECT count(*) FROM effects WHERE effect_key=?", (key,)).fetchone()[0]
