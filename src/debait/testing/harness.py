import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from debait.agent.loop import ContainmentAgent
from debait.agent.reasoner import FixtureReasoner
from debait.agent.scenario import CATALOG, build_scenario, case_spec
from debait.episodes.store import EpisodeStore
from debait.testing.world import FixtureWorld

CASES = set(CATALOG)


DEFAULT_MODEL_BUDGET_MICRODOLLARS = 300_000  # $0.30 cap per fresh-model run


def run_case(
    case: str,
    *,
    workspace: Path,
    mode: str = "local",
    reasoning_mode: str = "fixture",
    seed: int = 0,
    database_path: Path | None = None,
) -> dict:
    if mode != "local" or reasoning_mode not in {"fixture", "fresh_model"}:
        raise ValueError("Only local fixture or fresh_model execution is implemented")
    if case not in CASES:
        raise ValueError("Unknown scenario")
    return asyncio.run(_run(case, Path(workspace), seed, database_path, reasoning_mode))


def _build_reasoner(store, reasoning_mode: str):
    """Fixture reasoner by default; a real budget-capped OpenAI reasoner on request.

    In fresh_model mode the agent loop's interpretation is done by a live model
    (extraction + signals + next read); deterministic policy still decides actions.
    """
    if reasoning_mode != "fresh_model":
        return FixtureReasoner(), "deterministic_fixture"
    from decimal import Decimal

    from debait.agent.reasoner import ModelReasoner
    from debait.reasoning.budget import Budget
    from debait.reasoning.client import ModelClient, ModelConfig
    from debait.settings import Settings

    settings = Settings()
    if settings.openai_key is None:
        raise ValueError("DEBAIT_OPENAI_KEY is required for fresh_model reasoning")
    store.set_budget_limit(DEFAULT_MODEL_BUDGET_MICRODOLLARS)
    config = ModelConfig(
        model="gpt-5.6-luna",  # the extraction/interpretation tier; sol/terra also available
        input_usd_per_million=Decimal("0.20"),
        output_usd_per_million=Decimal("1.20"),
    )
    client = ModelClient(config, settings.openai_key, Budget(store), allow_network=True)
    return ModelReasoner(client), f"fresh_model:{config.model}"


async def _run(case, workspace, seed, database_path=None, reasoning_mode="fixture"):
    started = time.monotonic()
    run_id = str(uuid4())
    episode_id = f"sc-{run_id[:8]}"
    store = EpisodeStore(database_path or workspace / "episodes.sqlite")
    spec = case_spec(case)
    world = FixtureWorld(
        drop_response=spec.drop_response,
        client_observation=spec.client_observation,
        pi_scam_state=spec.pi_scam_state,
    )
    initial = world.snapshot()
    reasoner, reasoning_label = _build_reasoner(store, reasoning_mode)
    agent = ContainmentAgent(store, world, build_scenario(case), reasoner, episode_id=episode_id)
    trace = await agent.run()
    model_cost_microdollars = 0
    if reasoning_mode == "fresh_model":
        from debait.reasoning.budget import Budget

        model_cost_microdollars = Budget(store).snapshot()["spent_microdollars"]
    observations = agent._last_observations()
    controls = [
        "unrelated_email",
        "pi_unrelated",
        "other_call",
        "unrelated_message",
        "other_actor",
        "other_browser",
    ]
    snapshot = store.episode_snapshot(episode_id)
    result = {
        "run_id": run_id,
        "episode_id": episode_id,
        "case": case,
        "mode": "local",
        "reasoning_mode": reasoning_label,
        "model_cost_microdollars": model_cost_microdollars,
        "seed": seed,
        "episode_state": snapshot["state"],
        "world": world.snapshot(),
        "effects": dict(world.effects),
        "verification": {k: v.level for k, v in observations.items()},
        "actions": store.action_history(episode_id),
        "agent_trace": [step.model_dump() for step in trace],
        "iterations": sum(1 for step in trace if step.phase == "reason"),
        "unrelated_resource_diffs": [k for k in controls if initial[k] != world.states[k]],
        "acted_providers": sorted({k.split(".")[0] for k in world.effects}),
        "unauthorized_actions": sum(
            count for key, count in world.effects.items() if key.split(":", 1)[1] in controls
        ),
        "elapsed_seconds": time.monotonic() - started,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "limitation": (
            "Synthetic stateful world (fixture provider actions); reasoning by a live OpenAI model."
            if reasoning_mode == "fresh_model"
            else "Synthetic stateful world and deterministic extraction; no live providers or fresh model calls."
        ),
    }
    reports = workspace / "reports"
    reports.mkdir(exist_ok=True)
    (reports / f"{run_id}.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
