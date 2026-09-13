from datetime import datetime, timedelta, timezone

import pytest

from debait.episodes.consent import Consent
from debait.episodes.models import Event
from debait.episodes.store import EpisodeStore
from debait.protection.broker import Action, Broker
from debait.protection.policy import Target
from debait.protection.verify import is_contained
from debait.testing.world import FixtureWorld


def setup(tmp_path, world=None):
    store = EpisodeStore(tmp_path / "db.sqlite")
    now = datetime.now(timezone.utc)
    event = Event(
        event_id="e1",
        provider="driver",
        provider_event_id="seed",
        episode_id="sc1",
        observed_at=now,
        received_at=now,
        payload={"resource_id": "pi_scam", "account_id": "test"},
    )
    store.ingest(event)
    target = Target(provider="stripe", resource_id="pi_scam", operation="cancel")
    store.bind_resource("sc1", target, "test", ["e1"])
    store.save_consent(
        Consent(
            episode_id="sc1",
            scope=frozenset({("stripe", "pi_scam", "cancel")}),
            expires_at=now + timedelta(minutes=10),
        )
    )
    store.set_state("sc1", "CONTAINING")
    return (
        store,
        Broker(store, world or FixtureWorld()),
        Action(action_id="act-1", episode_id="sc1", target=target, policy_version="v1"),
    )


@pytest.mark.asyncio
async def test_cancel_is_scoped_and_read_back_verified(tmp_path):
    world = FixtureWorld()
    store, broker, action = setup(tmp_path, world)
    result = await broker.execute(action)
    assert result.state == "canceled"
    assert result.level == "read_back"
    assert world.snapshot()["pi_unrelated"] == "requires_confirmation"


@pytest.mark.asyncio
async def test_model_cannot_substitute_equal_amount_payment(tmp_path):
    world = FixtureWorld()
    store, broker, action = setup(tmp_path, world)
    wrong = action.model_copy(
        update={"target": Target(provider="stripe", resource_id="pi_unrelated", operation="cancel")}
    )
    with pytest.raises(PermissionError):
        await broker.execute(wrong)
    assert world.snapshot()["pi_unrelated"] == "requires_confirmation"


@pytest.mark.asyncio
async def test_duplicate_logical_action_survives_broker_restart(tmp_path):
    world = FixtureWorld()
    store, broker, action = setup(tmp_path, world)
    await broker.execute(action)
    await Broker(EpisodeStore(store.path), world).execute(
        action.model_copy(update={"action_id": "different-id"})
    )
    assert world.effects["stripe.cancel:pi_scam"] == 1


@pytest.mark.asyncio
async def test_timeout_after_success_reads_back_without_second_effect(tmp_path):
    world = FixtureWorld(drop_response=True)
    store, broker, action = setup(tmp_path, world)
    result = await broker.execute(action)
    assert result.state == "canceled" and result.level == "read_back"
    assert world.effects["stripe.cancel:pi_scam"] == 1


@pytest.mark.asyncio
async def test_revoked_consent_prevents_retry(tmp_path):
    world = FixtureWorld()
    store, broker, action = setup(tmp_path, world)
    store.revoke_consent("sc1")
    with pytest.raises(PermissionError):
        await broker.execute(action)
    assert world.snapshot()["pi_scam"] == "requires_confirmation"


def test_ack_is_not_complete_containment():
    assert not is_contained([{"required": True, "state": "removed", "level": "acknowledged", "fresh": True}])
    assert not is_contained([])
    assert not is_contained([{"required": False, "state": "unknown", "level": "requested", "fresh": True}])
    assert is_contained(
        [{"required": True, "operation": "cancel", "state": "canceled", "level": "read_back", "fresh": True}]
    )


def test_verifier_rejects_wrong_operation_outcome_and_missing_resource():
    from debait.protection.verify import verify_requirements

    now = datetime.now(timezone.utc)
    requirement = Target(provider="stripe", resource_id="pi_scam", operation="cancel")
    from debait.providers.base import Observation

    wrong = Observation(
        provider="stripe",
        resource_id="pi_scam",
        account_id="test",
        state="completed",
        level="read_back",
        observed_at=now,
        source="fixture",
    )
    assert not verify_requirements([requirement], [wrong], now)
    assert not verify_requirements([requirement], [], now)
    future = wrong.model_copy(update={"state": "canceled", "observed_at": now + timedelta(minutes=2)})
    assert not verify_requirements([requirement], [future], now)


def test_consent_revocation_preserves_history(tmp_path):
    store, broker, action = setup(tmp_path)
    store.revoke_consent("sc1")
    history = store.consent_history("sc1")
    assert [x["kind"] for x in history] == ["grant", "revoke"]
    assert history[0]["scope"] == [["stripe", "pi_scam", "cancel"]]
    assert store.consent("sc1") is None
