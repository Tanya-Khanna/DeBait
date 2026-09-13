import asyncio
from datetime import datetime, timezone
from typing import Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from debait.episodes.models import Event
from debait.episodes.store import EpisodeStore
from debait.hunter.indicators import attach_indicators


class DecoyMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    message_id: str = Field(min_length=1, max_length=160)
    text: str = Field(min_length=1, max_length=4000)


class DecoyAdapter(Protocol):
    world_kind: str
    context_id: str
    actor_id: str

    async def exchange(self, prompt: str) -> DecoyMessage: ...


class HunterLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_turns: int = Field(default=1, ge=1, le=1)
    timeout_seconds: float = Field(default=5, gt=0, le=15)


class HunterRun(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run_id: str
    state: Literal["blocked", "completed"]
    trace_ids: list[str]
    sent_messages: int
    reason: str | None = None
    reply_event_id: str | None = None
    indicator_event_ids: list[str] = Field(default_factory=list)


def _event(episode_id: str, provider_event_id: str, payload: dict) -> Event:
    now = datetime.now(timezone.utc)
    return Event(
        event_id=f"hunter:{uuid4()}",
        provider="hunter",
        provider_event_id=provider_event_id,
        episode_id=episode_id,
        observed_at=now,
        received_at=now,
        payload={**payload, "authority_scope": "decoy_observation_only"},
    )


async def start_hunter(
    episode_id: str,
    decoy_context_id: str,
    store: EpisodeStore,
    adapter: DecoyAdapter,
    *,
    victim_context_ids: set[str],
    allowed_actor_id: str,
    limits: HunterLimits | None = None,
) -> HunterRun:
    run_id = str(uuid4())
    snapshot = store.episode_snapshot(episode_id)
    if snapshot is None:
        raise ValueError("Episode not found")
    if snapshot["state"] != "CONTAINED":
        return HunterRun(
            run_id=run_id,
            state="blocked",
            trace_ids=[],
            sent_messages=0,
            reason="fresh_full_containment_required",
        )
    if decoy_context_id in victim_context_ids:
        raise PermissionError("Hunter context overlaps the victim context")
    if (
        adapter.world_kind != "fixture-world"
        or adapter.context_id != decoy_context_id
        or adapter.actor_id != allowed_actor_id
    ):
        raise PermissionError("Hunter adapter is outside the exact fixture decoy scope")
    limits = limits or HunterLimits()
    prompt = (
        "Where should I send the test payment? This is a controlled simulation. "
        "Use only demonstration identifiers."
    )
    outbound = _event(
        episode_id,
        f"{run_id}:outbound:1",
        {
            "direction": "outbound",
            "context_id": decoy_context_id,
            "actor_id": allowed_actor_id,
            "text": prompt,
            "turn": 1,
            "max_turns": limits.max_turns,
        },
    )
    store.ingest(outbound)
    try:
        async with asyncio.timeout(limits.timeout_seconds):
            reply = await adapter.exchange(prompt)
    except TimeoutError:
        return HunterRun(
            run_id=run_id,
            state="blocked",
            trace_ids=[outbound.event_id],
            sent_messages=1,
            reason="decoy_timeout",
        )
    inbound = _event(
        episode_id,
        f"{run_id}:inbound:{reply.message_id}",
        {
            "direction": "inbound",
            "context_id": decoy_context_id,
            "actor_id": allowed_actor_id,
            "text": reply.text,
            "turn": 1,
        },
    )
    store.ingest(inbound)
    _, indicator_event_ids = attach_indicators(store, episode_id, inbound.event_id)
    return HunterRun(
        run_id=run_id,
        state="completed",
        trace_ids=[outbound.event_id, inbound.event_id],
        sent_messages=1,
        reply_event_id=inbound.event_id,
        indicator_event_ids=indicator_event_ids,
    )
