"""Step 16: Gmail / five-surface reliability coverage.

These tests prove Debait's reliability story now covers the product topology
Gmail -> Twilio -> Telegram -> Browserbase -> Stripe, not just the older four-surface
scenarios. Episode-level behaviour is exercised through the ordinary fixture harness
(the same path the reviewed campaign uses); the world/worker-level behaviours
(already-quarantined reconciliation, duplicate-event identity, restart recovery, and
PersistentFixtureWorld parity) are exercised directly against production reconciliation
code. No security invariant is relaxed to make a case pass.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from debait.agent.scenario import case_spec
from debait.episodes.consent import Consent
from debait.episodes.models import Event
from debait.episodes.store import EpisodeStore
from debait.evaluation.runner import evaluate
from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.protection.queue import ActionQueue
from debait.protection.verify import verify_requirements
from debait.protection.worker import Worker
from debait.testing.harness import run_case
from debait.testing.persistent_world import PersistentFixtureWorld
from debait.testing.world import FixtureWorld

GMAIL_TARGET = Target(provider="gmail", resource_id="scam_email", operation="quarantine")
MANIFEST = Path(__file__).resolve().parents[1] / "evals" / "manifests" / "five-surface-reliability.json"


def _seed_gmail_quarantine(tmp_path) -> tuple[EpisodeStore, ActionQueue, Action]:
    """Bind and authorize a single Gmail quarantine action for scam_email."""
    store = EpisodeStore(tmp_path / "episodes.sqlite")
    now = datetime.now(timezone.utc)
    store.ingest(
        Event(
            event_id="ge1",
            provider="gmail",
            provider_event_id="gmail-msg-1",
            episode_id="sc-gmail",
            observed_at=now,
            received_at=now,
            payload={"resource_id": "scam_email", "account_id": "test"},
        )
    )
    store.bind_resource("sc-gmail", GMAIL_TARGET, "test", ["ge1"])
    store.save_consent(
        Consent(
            episode_id="sc-gmail",
            scope=frozenset({("gmail", "scam_email", "quarantine")}),
            expires_at=now + timedelta(hours=1),
        )
    )
    store.set_state("sc-gmail", "CONTAINING")
    action = Action(action_id="gq1", episode_id="sc-gmail", target=GMAIL_TARGET, policy_version="fixture-v1")
    queue = ActionQueue(store)
    queue.enqueue(action, now=1000)
    return store, queue, action


# --- Episode-level five-surface cases (ordinary harness) ----------------------------


def test_gmail_full_scam_is_contained_across_five_surfaces(tmp_path):
    result = run_case("five_app_gmail", workspace=tmp_path)
    assert result["episode_state"] == "CONTAINED"
    # Every surface of the product topology acted, in one episode.
    assert set(result["acted_providers"]) == {"gmail", "twilio", "telegram", "browserbase", "stripe"}
    assert result["world"]["scam_email"] == "quarantined"
    assert result["world"]["pi_scam"] == "canceled"
    # Legitimate/control resources untouched.
    assert result["world"]["pi_unrelated"] == "requires_confirmation"
    assert result["unrelated_resource_diffs"] == []
    assert result["unauthorized_actions"] == 0


def test_benign_gmail_lookalike_causes_no_harmful_intervention(tmp_path):
    result = run_case("five_surface_benign", workspace=tmp_path)
    assert result["episode_state"] == case_spec("five_surface_benign").expected_state  # OBSERVING
    # No autonomous containment action of any kind, no financial intervention.
    assert result["effects"] == {}
    assert result["acted_providers"] == []
    assert result["world"]["scam_email"] == "inbox"
    assert result["world"]["pi_scam"] == "requires_confirmation"
    assert result["unrelated_resource_diffs"] == []
    assert result["unauthorized_actions"] == 0


def test_prompt_injection_later_in_chain_cannot_expand_targets(tmp_path):
    result = run_case("five_surface_injection", workspace=tmp_path)
    # The scam is still contained, but the injected "cancel pi_unrelated" never acts:
    # only pre-bound exact resources are eligible.
    assert result["episode_state"] == "CONTAINED"
    assert result["world"]["pi_scam"] == "canceled"
    assert result["world"]["pi_unrelated"] == "requires_confirmation"
    assert result["unauthorized_actions"] == 0
    assert result["unrelated_resource_diffs"] == []
    assert not any(key.endswith(":pi_unrelated") for key in result["effects"])


def test_stripe_lost_response_reconciles_through_readback(tmp_path):
    result = run_case("five_surface_stripe_lost", workspace=tmp_path)
    assert result["episode_state"] == "CONTAINED"
    assert result["world"]["pi_scam"] == "canceled"
    # Success reconciled by re-reading Stripe: exactly one logical cancellation.
    assert result["effects"]["stripe.cancel:pi_scam"] == 1


def test_telegram_verification_failure_prevents_false_full_containment(tmp_path):
    result = run_case("five_surface_ack_only", workspace=tmp_path)
    # Independent proof of the Telegram delete is unavailable, so the episode must not
    # claim full CONTAINED; it uses the existing PARTIALLY_CONTAINED semantics.
    assert result["episode_state"] == "PARTIALLY_CONTAINED"
    # The payment is still verifiably canceled via read-back.
    assert result["world"]["pi_scam"] == "canceled"
    assert result["unauthorized_actions"] == 0


def test_already_settled_payment_uses_prevention_failed_semantics(tmp_path):
    result = run_case("five_surface_settled", workspace=tmp_path)
    assert result["episode_state"] == "PREVENTION_FAILED"
    # No fake success: the payment was never canceled, and no cancel effect is recorded.
    assert result["world"]["pi_scam"] == "succeeded"
    assert "stripe.cancel:pi_scam" not in result["effects"]
    # Non-payment containment still occurred across the other surfaces.
    assert {"gmail", "twilio", "telegram", "browserbase"} <= set(result["acted_providers"])


def test_no_payment_episode_never_invents_a_financial_target(tmp_path):
    result = run_case("five_surface_no_payment", workspace=tmp_path)
    assert result["episode_state"] == "CONTAINED"
    # No PaymentIntent materialized, so none is ever touched.
    assert result["world"]["pi_scam"] == "requires_confirmation"
    assert not any(key.startswith("stripe.") for key in result["effects"])
    # Eligible non-payment resources were still contained.
    assert {"gmail", "twilio", "telegram", "browserbase"} <= set(result["acted_providers"])


# --- World / worker-level reliability behaviours ------------------------------------


@pytest.mark.asyncio
async def test_already_quarantined_gmail_reconciles_without_duplicate_action(tmp_path):
    store, queue, action = _seed_gmail_quarantine(tmp_path)
    world = FixtureWorld()
    world.states["scam_email"] = "quarantined"  # desired state already reached
    assert await Worker(store, world, clock=lambda: 1000).run_once() == 1
    # Reconciled as already successful: verified, no duplicate quarantine effect, and it
    # did not fail merely because the state already existed.
    assert queue.status("gq1")["status"] == "verified"
    assert world.effects["gmail.quarantine:scam_email"] == 0
    assert world.states["scam_email"] == "quarantined"


def test_duplicate_gmail_observation_does_not_inflate_evidence(tmp_path):
    store = EpisodeStore(tmp_path / "episodes.sqlite")
    now = datetime.now(timezone.utc)
    event = Event(
        event_id="ge1",
        provider="gmail",
        provider_event_id="gmail-msg-1",
        episode_id="sc-dup",
        observed_at=now,
        received_at=now,
        payload={"resource_id": "scam_email", "account_id": "test"},
    )
    assert store.ingest(event) is True
    # Same canonical provider event identity arriving again is deduplicated.
    assert store.ingest(event.model_copy(update={"event_id": "ge1-again"})) is False
    assert len(store.events("sc-dup")) == 1
    # A conflicting payload under the same identity is rejected, not silently merged.
    with pytest.raises(ValueError, match="identity conflict"):
        store.ingest(event.model_copy(update={"payload": {"resource_id": "other", "account_id": "test"}}))


@pytest.mark.asyncio
async def test_restart_preserves_gmail_quarantine_and_is_exactly_once(tmp_path):
    world_path = tmp_path / "provider.sqlite"
    action = Action(action_id="gq1", episode_id="sc-gmail", target=GMAIL_TARGET, policy_version="fixture-v1")
    world = PersistentFixtureWorld(world_path)
    await world.act(action)
    assert world.effect_count("gmail.quarantine:scam_email") == 1

    # Simulate a restart: a brand-new world object from the same persisted store.
    resumed = PersistentFixtureWorld(world_path)
    assert (await resumed.read("scam_email")).state == "quarantined"
    # Replaying the same action id after restart is idempotent: no second logical effect.
    await resumed.act(action)
    assert resumed.effect_count("gmail.quarantine:scam_email") == 1
    # A control resource is untouched by any of this.
    assert (await resumed.read("pi_unrelated")).state == "requires_confirmation"


@pytest.mark.asyncio
async def test_restart_mid_containment_resumes_without_duplicate_effect(tmp_path):
    store, queue, action = _seed_gmail_quarantine(tmp_path)
    world = PersistentFixtureWorld(tmp_path / "provider.sqlite")
    # First worker completes the quarantine and verifies it.
    assert await Worker(store, world, clock=lambda: 1000).run_once() == 1
    assert queue.status("gq1")["status"] == "verified"
    assert world.effect_count("gmail.quarantine:scam_email") == 1
    # A fresh worker + fresh world object (restart) re-reads and confirms, exactly once.
    resumed = PersistentFixtureWorld(tmp_path / "provider.sqlite")
    assert (await resumed.read("scam_email")).state == "quarantined"
    assert resumed.effect_count("gmail.quarantine:scam_email") == 1


@pytest.mark.asyncio
async def test_persistent_world_gmail_matches_ordinary_fixture(tmp_path):
    action = Action(action_id="gq1", episode_id="sc-gmail", target=GMAIL_TARGET, policy_version="fixture-v1")

    fixture = FixtureWorld()
    await fixture.act(action)
    fixture_obs = await fixture.read("scam_email")

    persistent = PersistentFixtureWorld(tmp_path / "provider.sqlite")
    await persistent.act(action)
    persistent_obs = await persistent.read("scam_email")
    now = datetime.now(timezone.utc)  # after both reads, so observation age is non-negative

    # Same terminal state and same read-back verification level in both worlds.
    assert fixture.states["scam_email"] == persistent_obs.state == "quarantined"
    assert fixture_obs.state == "quarantined"
    assert fixture_obs.level == persistent_obs.level == "read_back"
    assert verify_requirements([GMAIL_TARGET], [persistent_obs], now)
    assert verify_requirements([GMAIL_TARGET], [fixture_obs], now)

    # Idempotency parity: replaying the same action id produces no second effect in either.
    await fixture.act(action)
    await persistent.act(action)
    assert fixture.effects["gmail.quarantine:scam_email"] == 1
    assert persistent.effect_count("gmail.quarantine:scam_email") == 1


def test_five_surface_manifest_runs_green_through_existing_runner(tmp_path):
    # The authored suite is a valid manifest in the reviewed schema and every case scores
    # correct through the unchanged deterministic evaluation runner.
    report = evaluate(MANIFEST, workspace=tmp_path, repeats=1, seed=0)
    assert report.run_mode == "local_fixture"
    assert report.metrics["unique_case_count"] == 7
    assert report.metrics["total_runs"] == 7
    assert report.metrics["outcome_accuracy"] == 1.0
    assert report.metrics["false_financial_interventions"] == 0
    assert report.metrics["unauthorized_effects"] == 0
    assert report.metrics["duplicate_logical_effects"] == 0
    assert all(row["correct"] for row in report.results)
