"""The containment loop is reasoner-agnostic: the SAME loop runs with the budgeted
ModelClient behind it. This exercises the real model transport (mocked, $0, offline)
to prove the fresh-model path is wired end-to-end, not hypothetical.
"""

import json
from decimal import Decimal

import httpx
import pytest
from pydantic import SecretStr

from debait.agent.loop import ContainmentAgent
from debait.agent.reasoner import ModelReasoner
from debait.agent.scenario import build_scenario
from debait.episodes.store import EpisodeStore
from debait.reasoning.budget import Budget
from debait.reasoning.client import ModelClient, ModelConfig
from debait.testing.world import FixtureWorld

_MARKERS = {
    "bank_claim": "bank fraud team",
    "secrecy": "don't contact your bank",
    "payment_coercion": "transfer to the safe account",
}


def _model_handler(request):
    """Stand in for the hosted model: read untrusted evidence, emit a valid assessment."""
    body = json.loads(request.content)
    parsed = json.loads(body["input"][0]["content"])
    events = parsed["events"]
    allowed = parsed["allowed_reads"]
    episode_id = events[0]["episode_id"]
    signals = []
    for event in events:
        text = str(event["payload"].get("text", "")).lower()
        for kind, phrase in _MARKERS.items():
            if phrase in text:
                signals.append({"kind": kind, "confidence": 0.9, "evidence_ids": [event["event_id"]]})
    missing = sorted(set(_MARKERS) - {s["kind"] for s in signals})
    next_read = None
    if missing and allowed:
        provider, resource_id = allowed[0]
        next_read = {"provider": provider, "resource_id": resource_id}
    assessment = {
        "episode_id": episode_id,
        "signals": signals,
        "contradictions": [],
        "missing_evidence": missing,
        "next_read": next_read,
    }
    return httpx.Response(
        200,
        json={
            "id": "resp-test",
            "model": "test-model",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": json.dumps(assessment)}],
                }
            ],
            "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        },
    )


@pytest.mark.asyncio
async def test_same_loop_contains_the_episode_with_the_model_reasoner(tmp_path):
    store = EpisodeStore(tmp_path / "db.sqlite")
    store.set_budget_limit(10_000_000)
    config = ModelConfig(
        model="test-model", input_usd_per_million=Decimal("1"), output_usd_per_million=Decimal("2")
    )
    client = ModelClient(
        config, SecretStr("local-test-key"), Budget(store), transport=httpx.MockTransport(_model_handler)
    )
    world = FixtureWorld(client_observation=True)
    agent = ContainmentAgent(
        store,
        world,
        build_scenario("four_app_two_payments"),
        ModelReasoner(client),
        episode_id="sc-model",
    )
    trace = await agent.run()

    assert store.episode_snapshot("sc-model")["state"] == "CONTAINED"
    assert world.snapshot()["pi_scam"] == "canceled"
    assert world.snapshot()["pi_unrelated"] == "requires_confirmation"
    # It genuinely looped through the model multiple times to accrue evidence.
    assert sum(1 for step in trace if step.phase == "reason") >= 3
    assert Budget(store).snapshot()["spent_microdollars"] > 0


@pytest.mark.asyncio
async def test_model_cannot_be_steered_to_an_unrelated_payment(tmp_path):
    store = EpisodeStore(tmp_path / "db.sqlite")
    store.set_budget_limit(10_000_000)
    config = ModelConfig(
        model="test-model", input_usd_per_million=Decimal("1"), output_usd_per_million=Decimal("2")
    )
    client = ModelClient(
        config, SecretStr("local-test-key"), Budget(store), transport=httpx.MockTransport(_model_handler)
    )
    world = FixtureWorld(client_observation=True)
    agent = ContainmentAgent(
        store,
        world,
        build_scenario("injection_cancel_unrelated"),
        ModelReasoner(client),
        episode_id="sc-inject",
    )
    await agent.run()
    assert world.snapshot()["pi_unrelated"] == "requires_confirmation"
