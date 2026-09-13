from datetime import datetime, timezone

import pytest

from debait.episodes.models import Event
from debait.episodes.store import EpisodeStore
from debait.hunter.runner import DecoyMessage, HunterLimits, start_hunter


class FixtureDecoy:
    world_kind = "fixture-world"
    context_id = "decoy-chat-1"
    actor_id = "controlled-attacker"

    def __init__(self):
        self.prompts = []

    async def exchange(self, prompt: str) -> DecoyMessage:
        self.prompts.append(prompt)
        return DecoyMessage(
            message_id="decoy-reply-1",
            text="Use @mule_demo or https://pay.example.test/checkout",
        )


def seeded_store(tmp_path, state):
    store = EpisodeStore(tmp_path / "episodes.sqlite")
    now = datetime.now(timezone.utc)
    store.ingest(
        Event(
            event_id="source-1",
            provider="driver",
            provider_event_id="source-1",
            episode_id="sc1",
            observed_at=now,
            received_at=now,
            payload={"scenario_mode": "local"},
        )
    )
    store.set_state("sc1", state)
    return store


@pytest.mark.asyncio
async def test_hunter_does_not_start_before_full_containment(tmp_path):
    store = seeded_store(tmp_path, "PARTIALLY_CONTAINED")
    adapter = FixtureDecoy()

    run = await start_hunter(
        "sc1",
        "decoy-chat-1",
        store,
        adapter,
        victim_context_ids={"victim-chat"},
        allowed_actor_id="controlled-attacker",
    )

    assert run.state == "blocked"
    assert run.sent_messages == 0
    assert adapter.prompts == []


@pytest.mark.asyncio
async def test_hunter_uses_only_allowlisted_fixture_decoy_and_records_trace(tmp_path):
    store = seeded_store(tmp_path, "CONTAINED")
    adapter = FixtureDecoy()

    run = await start_hunter(
        "sc1",
        "decoy-chat-1",
        store,
        adapter,
        victim_context_ids={"victim-chat"},
        allowed_actor_id="controlled-attacker",
        limits=HunterLimits(max_turns=1, timeout_seconds=2),
    )

    assert run.state == "completed"
    assert run.sent_messages == 1
    assert len(run.trace_ids) == 2
    assert "test payment" in adapter.prompts[0]
    hunter_events = [
        e
        for e in store.events("sc1")
        if e.provider == "hunter" and e.payload["authority_scope"] == "decoy_observation_only"
    ]
    assert len(hunter_events) == 2
    assert all(e.payload["authority_scope"] == "decoy_observation_only" for e in hunter_events)
    indicator_events = [
        e for e in store.events("sc1") if e.provider == "hunter" and e.payload.get("direction") == "indicator"
    ]
    assert {e.payload["value"] for e in indicator_events} == {
        "@mule_demo",
        "pay.example.test",
    }
    assert all(e.payload["claim_status"] == "attacker_supplied" for e in indicator_events)
    assert set(run.indicator_event_ids) == {e.event_id for e in indicator_events}


@pytest.mark.asyncio
async def test_hunter_rejects_victim_context_and_nonfixture_world(tmp_path):
    store = seeded_store(tmp_path, "CONTAINED")
    adapter = FixtureDecoy()
    adapter.world_kind = "telegram-live-test"

    with pytest.raises(PermissionError):
        await start_hunter(
            "sc1",
            "victim-chat",
            store,
            adapter,
            victim_context_ids={"victim-chat"},
            allowed_actor_id="controlled-attacker",
        )
