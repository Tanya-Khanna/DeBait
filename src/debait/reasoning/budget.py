from debait.episodes.store import EpisodeStore


class Budget:
    def __init__(self, store: EpisodeStore):
        self.store = store

    def reserve(self, request_id: str, maximum_microdollars: int) -> bool:
        if not request_id or type(maximum_microdollars) is not int or maximum_microdollars <= 0:
            raise ValueError("Positive integer reservation and unique request ID required")
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM usage_reservations WHERE request_id=?", (request_id,)).fetchone():
                return False
            total = db.execute(
                "SELECT COALESCE(SUM(CASE WHEN state='settled' THEN actual ELSE amount END),0) FROM usage_reservations"
            ).fetchone()[0]
            limit = db.execute("SELECT limit_microdollars FROM budget_config WHERE id=1").fetchone()[0]
            if total + maximum_microdollars > limit:
                return False
            db.execute(
                "INSERT INTO usage_reservations(request_id,amount) VALUES(?,?)",
                (request_id, maximum_microdollars),
            )
            return True

    def settle(self, request_id: str, actual_microdollars: int | None) -> None:
        if actual_microdollars is not None and (
            type(actual_microdollars) is not int or actual_microdollars < 0
        ):
            raise ValueError("Nonnegative integer cost required")
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM usage_reservations WHERE request_id=?", (request_id,)).fetchone()
            if not row:
                raise ValueError("Unknown request reservation")
            if row["state"] == "settled":
                if row["actual"] != actual_microdollars:
                    raise ValueError("Settled cost is immutable")
                return
            if actual_microdollars is not None:
                # Record overrun truthfully and exhaust the cap; never silently clamp billed cost.
                db.execute(
                    "UPDATE usage_reservations SET state='settled',actual=? WHERE request_id=?",
                    (actual_microdollars, request_id),
                )

    def snapshot(self) -> dict:
        with self.store.connection() as db:
            limit = db.execute("SELECT limit_microdollars FROM budget_config WHERE id=1").fetchone()[0]
            spent, reserved = db.execute(
                "SELECT COALESCE(SUM(CASE WHEN state='settled' THEN actual ELSE 0 END),0),COALESCE(SUM(CASE WHEN state='reserved' THEN amount ELSE 0 END),0) FROM usage_reservations"
            ).fetchone()
        return {
            "limit_microdollars": limit,
            "spent_microdollars": spent,
            "reserved_microdollars": reserved,
            "available_microdollars": max(0, limit - spent - reserved),
        }
