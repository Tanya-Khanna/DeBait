import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from debait.episodes.consent import Consent
from debait.episodes.models import Event
from debait.episodes.store import EpisodeStore
from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.protection.queue import ActionQueue
from debait.protection.worker import Worker
from debait.providers.base import RetryAfter
from debait.testing.persistent_world import PersistentFixtureWorld


def seed(tmp_path):
    store = EpisodeStore(tmp_path / "episodes.sqlite")
    now = datetime.now(timezone.utc)
    store.ingest(
        Event(
            event_id="e1",
            provider="driver",
            provider_event_id="s1",
            episode_id="sc1",
            observed_at=now,
            received_at=now,
            payload={"resource_id": "pi_scam", "account_id": "test"},
        )
    )
    target = Target(provider="stripe", resource_id="pi_scam", operation="cancel")
    store.bind_resource("sc1", target, "test", ["e1"])
    store.save_consent(
        Consent(
            episode_id="sc1",
            scope=frozenset({("stripe", "pi_scam", "cancel")}),
            expires_at=now + timedelta(hours=1),
        )
    )
    store.set_state("sc1", "CONTAINING")
    action = Action(action_id="a1", episode_id="sc1", target=target, policy_version="v1")
    q = ActionQueue(store)
    q.enqueue(action, now=1000)
    return store, q, action


def test_only_one_worker_claims_a_job(tmp_path):
    store, q, action = seed(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(
            pool.map(lambda n: ActionQueue(EpisodeStore(store.path)).claim(str(n), now=1000), range(8))
        )
    assert sum(c is not None for c in claims) == 1


def test_expired_worker_cannot_finish_new_owners_job(tmp_path):
    store, q, action = seed(tmp_path)
    q.claim("old", now=1000)
    assert q.claim("new", now=1031)
    assert not q.finish("a1", "old", "verified", now=1032)
    assert q.status("a1")["owner"] == "new"


@pytest.mark.asyncio
async def test_process_crash_after_effect_reconciles_without_second_effect(tmp_path):
    store, q, action = seed(tmp_path)
    world_path = tmp_path / "provider.sqlite"
    PersistentFixtureWorld(world_path)
    script = """
import asyncio,os,sys
from pathlib import Path
from debait.episodes.store import EpisodeStore
from debait.protection.queue import ActionQueue
from debait.protection.broker import Action
from debait.testing.persistent_world import PersistentFixtureWorld
q=ActionQueue(EpisodeStore(Path(sys.argv[1])))
job=q.claim('crashed',now=1000)
asyncio.run(PersistentFixtureWorld(Path(sys.argv[2])).act(Action.model_validate(job['action'])))
os._exit(23)
"""
    p = subprocess.run([sys.executable, "-c", script, str(store.path), str(world_path)], capture_output=True)
    assert p.returncode == 23, p.stderr.decode()
    assert q.status("a1")["status"] == "running"
    world = PersistentFixtureWorld(world_path)
    assert await Worker(EpisodeStore(store.path), world, clock=lambda: 1031).run_once() == 1
    assert q.status("a1")["status"] == "verified"
    assert world.effect_count("stripe.cancel:pi_scam") == 1
    assert (await world.read("pi_unrelated")).state == "requires_confirmation"


@pytest.mark.asyncio
async def test_rate_limit_waits_then_reconciles(tmp_path):
    store, q, action = seed(tmp_path)
    world = PersistentFixtureWorld(tmp_path / "world.sqlite")

    class RateLimited:
        async def read(self, id):
            raise RetryAfter(12)

        async def act(self, a):
            raise AssertionError("Must not write when read is unavailable")

    assert await Worker(store, RateLimited(), clock=lambda: 1000).run_once() == 1
    assert q.status("a1")["due_at"] == 1012
    assert await Worker(store, world, clock=lambda: 1011).run_once() == 0
    assert await Worker(store, world, clock=lambda: 1012).run_once() == 1
    assert q.status("a1")["status"] == "verified"


@pytest.mark.asyncio
async def test_revoked_consent_blocks_queued_payment(tmp_path):
    store, q, action = seed(tmp_path)
    store.revoke_consent("sc1")
    world = PersistentFixtureWorld(tmp_path / "world.sqlite")
    await Worker(store, world, clock=lambda: 1000).run_once()
    assert q.status("a1")["status"] == "blocked"
    assert (await world.read("pi_scam")).state == "requires_confirmation"


@pytest.mark.asyncio
async def test_succeeded_race_records_failed_prevention(tmp_path):
    store, q, action = seed(tmp_path)
    world = PersistentFixtureWorld(tmp_path / "world.sqlite")
    with world.connection() as db:
        db.execute("UPDATE resources SET state='succeeded' WHERE id='pi_scam'")
    await Worker(store, world, clock=lambda: 1000).run_once()
    assert q.status("a1")["status"] == "prevention_failed"
    assert store.episode_snapshot("sc1")["state"] == "PREVENTION_FAILED"
    assert world.effect_count("stripe.cancel:pi_scam") == 0


@pytest.mark.asyncio
async def test_retries_are_bounded_without_a_payment_effect(tmp_path):
    store, q, action = seed(tmp_path)

    class Offline:
        async def read(self, id):
            raise ConnectionError("offline")

        async def act(self, a):
            raise AssertionError("No write during outage")

    for n in range(3):
        await Worker(store, Offline(), clock=lambda n=n: 1000 + 100 * n, max_attempts=3).run_once()
    assert q.status("a1")["status"] == "review_required"
    assert await Worker(store, Offline(), clock=lambda: 2000, max_attempts=3).run_once() == 0


def test_enqueue_rolls_back_action_if_job_persistence_fails(tmp_path):
    store, q, action = seed(tmp_path)
    other = action.model_copy(update={"action_id": "a2", "policy_version": "v2"})
    with store.connection() as db:
        db.execute(
            "CREATE TRIGGER reject_job BEFORE INSERT ON action_jobs WHEN NEW.action_id='a2' BEGIN SELECT RAISE(ABORT,'disk failure simulation'); END"
        )
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        q.enqueue(other, now=1000)
    with store.connection() as db:
        assert db.execute("SELECT 1 FROM actions WHERE action_id='a2'").fetchone() is None


@pytest.mark.asyncio
async def test_stale_provider_state_cannot_authorize_a_write(tmp_path):
    store, q, action = seed(tmp_path)
    world = PersistentFixtureWorld(tmp_path / "world.sqlite")

    class Stale:
        async def read(self, id):
            value = await world.read(id)
            return value.model_copy(update={"observed_at": datetime.now(timezone.utc) - timedelta(hours=1)})

        async def act(self, a):
            return await world.act(a)

    await Worker(store, Stale(), clock=lambda: 1000).run_once()
    assert world.effect_count("stripe.cancel:pi_scam") == 0
    assert q.status("a1")["status"] == "blocked"


@pytest.mark.asyncio
async def test_payment_succeeds_between_read_and_cancel(tmp_path):
    store, q, action = seed(tmp_path)
    world = PersistentFixtureWorld(tmp_path / "world.sqlite")

    class Racing:
        async def read(self, id):
            return await world.read(id)

        async def act(self, a):
            with world.connection() as db:
                db.execute("UPDATE resources SET state='succeeded' WHERE id='pi_scam'")
            return await world.act(a)

    await Worker(store, Racing(), clock=lambda: 1000).run_once()
    assert q.status("a1")["status"] == "prevention_failed"
    assert world.effect_count("stripe.cancel:pi_scam") == 0


def test_payment_job_has_priority_over_earlier_call(tmp_path):
    store, q, action = seed(tmp_path)
    call = action.model_copy(
        update={
            "action_id": "call-a",
            "target": Target(provider="twilio", resource_id="scam_call", operation="end"),
        }
    )
    q.enqueue(call, now=900)
    assert q.claim("worker", now=1000)["action"]["target"]["provider"] == "stripe"


@pytest.mark.asyncio
async def test_repeated_crashes_do_not_bypass_retry_cap(tmp_path):
    store, q, action = seed(tmp_path)
    world = PersistentFixtureWorld(tmp_path / "world.sqlite")
    for n in range(3):
        assert q.claim(str(n), now=1000 + 31 * n)
    await Worker(store, world, clock=lambda: 1100, max_attempts=3).run_once()
    assert q.status("a1")["status"] == "review_required"
    assert world.effect_count("stripe.cancel:pi_scam") == 0
