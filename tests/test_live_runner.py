from datetime import datetime, timezone

import pytest

from debait.episodes.store import EpisodeStore
from debait.live import LiveEpisodeRunner, LiveResource
from debait.protection.router import ProviderRouter
from debait.providers.base import Observation, Receipt
from debait.reasoning.client import ModelUnavailable
from debait.reasoning.schema import Assessment, ReadRequest, Signal

TERMINAL = {
    "quarantine": "quarantined",
    "end": "completed",
    "delete": "removed",
    "ban": "banned",
    "release": "terminated",
    "cancel": "canceled",
}


class StatefulAdapter:
    def __init__(
        self,
        provider,
        account_id,
        states,
        texts=None,
        *,
        lost_response=False,
        verify=False,
        read_error=False,
    ):
        self.provider = provider
        self.account_id = account_id
        self.states = dict(states)
        self.texts = texts or {}
        self.lost_response = lost_response
        self.verify = verify
        self.read_error = read_error
        self.reads = []
        self.acts = []

    async def read(self, resource_id):
        self.reads.append(resource_id)
        if self.read_error:
            raise ConnectionError("provider unavailable")
        if resource_id not in self.states:
            raise PermissionError("unregistered fake resource")
        return Observation(
            provider=self.provider,
            resource_id=resource_id,
            account_id=self.account_id,
            state=self.states[resource_id],
            level="read_back",
            observed_at=datetime.now(timezone.utc),
            source=f"{self.provider}.read",
            details={"text": self.texts.get(resource_id, "")},
        )

    async def act(self, action):
        self.acts.append(action.target.resource_id)
        if not self.verify:
            self.states[action.target.resource_id] = TERMINAL[action.target.operation]
        if self.lost_response:
            self.lost_response = False
            raise ConnectionError("response lost after provider mutation")
        return Receipt(request_id=f"{self.provider}:request", acknowledged=True)


class EvidenceReasoner:
    async def assess(self, events, *, allowed_reads=frozenset()):
        observed = [event for event in events if event.provider != "driver"]
        if len(observed) < 2:
            provider, resource_id = sorted(allowed_reads)[0]
            return Assessment(
                episode_id=events[0].episode_id,
                signals=[
                    Signal(
                        kind="bank_claim",
                        confidence=0.95,
                        evidence_ids=[observed[0].event_id],
                    )
                ],
                next_read=ReadRequest(provider=provider, resource_id=resource_id),
            )
        return Assessment(
            episode_id=events[0].episode_id,
            signals=[
                Signal(kind="bank_claim", confidence=0.95, evidence_ids=[observed[0].event_id]),
                Signal(kind="secrecy", confidence=0.95, evidence_ids=[observed[1].event_id]),
                Signal(
                    kind="payment_coercion",
                    confidence=0.95,
                    evidence_ids=[observed[1].event_id],
                ),
            ],
        )


class InventedReadReasoner:
    async def assess(self, events, *, allowed_reads=frozenset()):
        return Assessment(
            episode_id=events[0].episode_id,
            next_read=ReadRequest(provider="stripe", resource_id="pi_invented"),
        )


class ControlReadReasoner:
    async def assess(self, events, *, allowed_reads=frozenset()):
        return Assessment(
            episode_id=events[0].episode_id,
            next_read=ReadRequest(provider="stripe", resource_id="pi_control"),
        )


class UnavailableReasoner:
    async def assess(self, events, *, allowed_reads=frozenset()):
        raise ModelUnavailable("test model unavailable")


def resources(shared_id=False):
    gmail_id = "shared" if shared_id else "gmail-message"
    browserbase_id = "shared" if shared_id else "browser-session"
    return [
        LiveResource(
            provider="gmail",
            resource_id=gmail_id,
            account_id="me",
            operation="quarantine",
        ),
        LiveResource(
            provider="browserbase",
            resource_id=browserbase_id,
            account_id="project_test",
            operation="release",
            parent_provider="gmail",
            parent_resource_id=gmail_id,
            edge_kind="observed_navigation",
        ),
        LiveResource(
            provider="stripe",
            resource_id="pi_scam",
            account_id="acct_test",
            operation="cancel",
            parent_provider="browserbase",
            parent_resource_id=browserbase_id,
            edge_kind="observed_payment_origin",
        ),
        LiveResource(
            provider="stripe",
            resource_id="pi_control",
            account_id="acct_test",
            operation="observe",
            role="control",
        ),
    ]


def build_runner(tmp_path, reasoner=None, *, stripe_kwargs=None, shared_id=False):
    selected = resources(shared_id)
    gmail = StatefulAdapter(
        "gmail",
        "me",
        {selected[0].resource_id: "inbox"},
        {selected[0].resource_id: "adapter bank fraud evidence"},
    )
    browserbase = StatefulAdapter(
        "browserbase",
        "project_test",
        {selected[1].resource_id: "running"},
        {selected[1].resource_id: "secure verification page"},
    )
    stripe = StatefulAdapter(
        "stripe",
        "acct_test",
        {selected[2].resource_id: "requires_confirmation", "pi_control": "requires_confirmation"},
        {selected[2].resource_id: "scam-linked payment"},
        **(stripe_kwargs or {}),
    )
    store = EpisodeStore(tmp_path / "live.sqlite")
    runner = LiveEpisodeRunner(
        store,
        ProviderRouter({"gmail": gmail, "browserbase": browserbase, "stripe": stripe}),
        selected,
        reasoner or EvidenceReasoner(),
        episode_id="live-episode",
        drain_timeout_seconds=0,
    )
    return runner, store, gmail, browserbase, stripe


@pytest.mark.asyncio
async def test_live_runner_reads_same_id_from_the_correct_provider_and_uses_no_fixture_effects(tmp_path):
    runner, store, gmail, browserbase, stripe = build_runner(tmp_path, shared_id=True)

    result = await runner.run()

    assert result.state == "CONTAINED"
    assert gmail.reads and browserbase.reads and stripe.reads
    assert gmail.acts == ["shared"] and browserbase.acts == ["shared"]
    assert stripe.acts == ["pi_scam"]
    assert result.verification["gmail:shared"] == "quarantined"
    assert result.verification["browserbase:shared"] == "terminated"
    assert result.verification["stripe:pi_scam"] == "canceled"
    assert not hasattr(runner.router, "effects")
    observed = [event for event in store.events("live-episode") if event.provider != "driver"]
    assert observed[0].payload["text"] == "adapter bank fraud evidence"
    assert observed[0].payload["provider_metadata"] == {}


@pytest.mark.asyncio
async def test_unbound_resource_cannot_be_read(tmp_path):
    runner, _, _, _, stripe = build_runner(tmp_path)
    await runner.register()

    with pytest.raises(PermissionError, match="registered and bound"):
        await runner.observe("stripe", "pi_invented")
    assert stripe.reads == []


@pytest.mark.asyncio
async def test_model_cannot_invent_a_read_or_create_a_write_target(tmp_path):
    runner, store, gmail, browserbase, stripe = build_runner(tmp_path, InventedReadReasoner())

    result = await runner.run()

    assert result.state == "REVIEW_REQUIRED"
    assert gmail.acts == [] and browserbase.acts == [] and stripe.acts == []
    assert store.action_history("live-episode") == []
    assert "pi_invented" not in stripe.reads


@pytest.mark.asyncio
async def test_stripe_control_is_untouched_and_verification_uses_provider_readback(tmp_path):
    runner, store, _, _, stripe = build_runner(tmp_path)

    result = await runner.run(control_payment=("stripe", "pi_control"))

    assert result.state == "CONTAINED"
    assert stripe.states["pi_scam"] == "canceled"
    assert stripe.states["pi_control"] == "requires_confirmation"
    assert stripe.acts == ["pi_scam"]
    scam, control = resources()[2:]
    assert store.binding("live-episode", scam.target) is not None
    assert store.binding("live-episode", control.target) is not None
    assert control.target not in runner.eligible_targets
    assert (control.provider, control.resource_id, control.operation) not in store.consent(
        "live-episode"
    ).scope
    assert await runner.read_registered("stripe", "pi_scam")
    assert await runner.read_registered("stripe", "pi_control")
    stripe_history = next(
        action for action in store.action_history("live-episode") if action["target"]["provider"] == "stripe"
    )
    assert stripe_history["observations"][-1]["state"] == "canceled"
    assert stripe.reads.count("pi_scam") >= 3
    assert "pi_control" in stripe.reads


@pytest.mark.asyncio
async def test_model_cannot_turn_bound_control_payment_into_a_write_target(tmp_path):
    runner, store, gmail, browserbase, stripe = build_runner(tmp_path, ControlReadReasoner())

    result = await runner.run(control_payment=("stripe", "pi_control"))

    assert result.state == "REVIEW_REQUIRED"
    assert gmail.acts == [] and browserbase.acts == [] and stripe.acts == []
    assert store.action_history("live-episode") == []


@pytest.mark.asyncio
async def test_lost_response_reconciles_without_duplicate_action(tmp_path):
    runner, store, _, _, stripe = build_runner(tmp_path, stripe_kwargs={"lost_response": True})

    result = await runner.run()

    assert result.state == "CONTAINED"
    assert stripe.acts == ["pi_scam"]
    history = next(
        action for action in store.action_history("live-episode") if action["target"]["provider"] == "stripe"
    )
    assert any(attempt["phase"] == "uncertain_response" for attempt in history["attempts"])


@pytest.mark.asyncio
async def test_restart_rereads_verified_effects_without_duplicate_mutation(tmp_path):
    runner, store, gmail, browserbase, stripe = build_runner(tmp_path)
    assert (await runner.run()).state == "CONTAINED"

    restarted = LiveEpisodeRunner(
        store,
        ProviderRouter({"gmail": gmail, "browserbase": browserbase, "stripe": stripe}),
        resources(),
        EvidenceReasoner(),
        episode_id="live-episode",
        drain_timeout_seconds=0,
    )
    result = await restarted.run()

    assert result.state == "CONTAINED"
    assert gmail.acts == ["gmail-message"]
    assert browserbase.acts == ["browser-session"]
    assert stripe.acts == ["pi_scam"]


@pytest.mark.asyncio
async def test_provider_verification_failure_prevents_false_contained(tmp_path):
    runner, _, _, _, stripe = build_runner(tmp_path, stripe_kwargs={"verify": True})

    result = await runner.run()

    assert result.state == "PARTIALLY_CONTAINED"
    assert stripe.states["pi_scam"] == "requires_confirmation"


@pytest.mark.asyncio
async def test_model_unavailable_routes_to_review_without_provider_write(tmp_path):
    runner, store, gmail, browserbase, stripe = build_runner(tmp_path, UnavailableReasoner())

    result = await runner.run()

    assert result.state == "REVIEW_REQUIRED"
    assert gmail.acts == [] and browserbase.acts == [] and stripe.acts == []
    assert store.action_history("live-episode") == []


@pytest.mark.asyncio
async def test_preflight_provider_failure_creates_no_mutation(tmp_path):
    runner, store, gmail, browserbase, stripe = build_runner(tmp_path)
    stripe.read_error = True

    result = await runner.run()

    assert result.state == "REVIEW_REQUIRED"
    assert gmail.acts == [] and browserbase.acts == [] and stripe.acts == []
    assert store.action_history("live-episode") == []


@pytest.mark.asyncio
async def test_one_persistent_episode_orchestrates_all_five_provider_adapters(tmp_path):
    selected = [
        LiveResource(provider="gmail", resource_id="m1", account_id="me", operation="quarantine"),
        LiveResource(
            provider="twilio",
            resource_id="call1",
            account_id="acct_twilio",
            operation="end",
            parent_provider="gmail",
            parent_resource_id="m1",
            edge_kind="channel_migration",
        ),
        LiveResource(
            provider="telegram",
            resource_id="message:1:2",
            account_id="bot:3",
            operation="delete",
            parent_provider="twilio",
            parent_resource_id="call1",
            edge_kind="channel_migration",
        ),
        LiveResource(
            provider="browserbase",
            resource_id="session1",
            account_id="project1",
            operation="release",
            parent_provider="telegram",
            parent_resource_id="message:1:2",
            edge_kind="observed_navigation",
        ),
        LiveResource(
            provider="stripe",
            resource_id="pi_scam",
            account_id="acct_test",
            operation="cancel",
            parent_provider="browserbase",
            parent_resource_id="session1",
            edge_kind="observed_payment_origin",
        ),
    ]
    adapters = {
        "gmail": StatefulAdapter("gmail", "me", {"m1": "inbox"}, {"m1": "bank claim"}),
        "twilio": StatefulAdapter("twilio", "acct_twilio", {"call1": "in-progress"}, {"call1": "urgent"}),
        "telegram": StatefulAdapter(
            "telegram", "bot:3", {"message:1:2": "present"}, {"message:1:2": "keep secret"}
        ),
        "browserbase": StatefulAdapter(
            "browserbase", "project1", {"session1": "active"}, {"session1": "payment page"}
        ),
        "stripe": StatefulAdapter("stripe", "acct_test", {"pi_scam": "requires_confirmation"}),
    }
    store = EpisodeStore(tmp_path / "five-provider.sqlite")
    runner = LiveEpisodeRunner(
        store,
        ProviderRouter(adapters),
        selected,
        EvidenceReasoner(),
        episode_id="five-provider-episode",
        drain_timeout_seconds=0,
    )

    result = await runner.run()

    assert result.state == "CONTAINED"
    assert {event.provider for event in store.events(result.episode_id)} >= {
        "gmail",
        "twilio",
        "telegram",
        "browserbase",
        "stripe",
    }
    assert {action["target"]["provider"] for action in result.actions} == set(adapters)
