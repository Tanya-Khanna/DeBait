import asyncio
import time
from datetime import datetime, timezone
from uuid import uuid4

from debait.protection.broker import Action, Broker
from debait.protection.policy import Target
from debait.protection.queue import ActionQueue
from debait.protection.verify import verify_requirements
from debait.providers.base import Observation, RetryAfter


class Worker:
    def __init__(self, store, adapter, *, clock=time.time, max_attempts=5):
        if not 1 <= max_attempts <= 20:
            raise ValueError("Retry cap must be between 1 and 20")
        self.store = store
        self.adapter = adapter
        self.clock = clock
        self.max_attempts = max_attempts
        self.queue = ActionQueue(store)
        self.owner = str(uuid4())

    async def run_once(self) -> int:
        job = self.queue.claim(self.owner, now=self.clock())
        if job is None:
            return 0
        action = Action.model_validate(job["action"])
        if job["attempts"] > self.max_attempts:
            if self.queue.finish(
                action.action_id,
                self.owner,
                "review_required",
                now=self.clock(),
                error="Retry budget exhausted after interrupted attempts",
            ):
                self.store.record_attempt(
                    action.action_id,
                    {
                        "phase": "worker_outcome",
                        "status": "review_required",
                        "error": "Interrupted attempts exhausted retry budget",
                    },
                )
                self.refresh_episode(action.episode_id)
            return 1

        def lease_guard():
            if not self.queue.owns(action.action_id, self.owner, now=self.clock()):
                raise PermissionError("Worker lease no longer valid")

        status = "retry"
        delay = min(60, 2 ** job["attempts"])
        error = None
        try:
            observation = await asyncio.wait_for(
                Broker(self.store, self.adapter, lease_guard=lease_guard).execute(action), timeout=8
            )
            now = datetime.now(timezone.utc)
            if verify_requirements([action.target], [observation], now):
                status = "verified"
            elif action.target.operation == "cancel" and observation.state == "succeeded":
                status = "prevention_failed"
            elif observation.source == "permission_denied":
                status = "blocked"
            else:
                error = "Outcome not independently verified"
        except RetryAfter as exc:
            delay = max(delay, exc.seconds)
            error = "Provider rate limit"
        except (TimeoutError, ConnectionError):
            error = "Provider unavailable; reconcile before another write"
        except PermissionError:
            status = "blocked"
            error = "Authority or provider identity check failed"
        except ValueError:
            status = "review_required"
            error = "Invalid provider transition or action contract"
        if status == "retry" and job["attempts"] >= self.max_attempts:
            status = "review_required"
            error = "Retry budget exhausted; outcome remains unverified"
        finished = self.queue.finish(
            action.action_id, self.owner, status, now=self.clock(), due_at=self.clock() + delay, error=error
        )
        if finished:
            self.store.record_attempt(
                action.action_id,
                {"phase": "worker_outcome", "status": status, "attempt": job["attempts"], "error": error},
            )
            self.refresh_episode(action.episode_id)
        return 1

    def refresh_episode(self, episode_id):
        with self.store.connection() as db:
            jobs = db.execute(
                "SELECT j.status FROM action_jobs j JOIN actions a USING(action_id) WHERE a.episode_id=?",
                (episode_id,),
            ).fetchall()
            bindings = db.execute(
                "SELECT provider,resource_id,operation FROM bindings WHERE episode_id=?", (episode_id,)
            ).fetchall()
        if any(j["status"] == "prevention_failed" for j in jobs):
            self.store.set_state(episode_id, "PREVENTION_FAILED")
            return
        requirements = [Target(**dict(row)) for row in bindings]
        observations = [
            Observation.model_validate(h["observations"][-1])
            for h in self.store.action_history(episode_id)
            if h["observations"]
        ]
        complete = all(j["status"] == "verified" for j in jobs) and verify_requirements(
            requirements, observations, datetime.now(timezone.utc)
        )
        self.store.set_state(episode_id, "CONTAINED" if complete else "PARTIALLY_CONTAINED")
