import asyncio
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

from debait.episodes.consent import permits
from debait.episodes.store import EpisodeStore
from debait.protection.policy import Target
from debait.protection.verify import terminal_states_for
from debait.providers.base import Observation, ProviderAdapter, ProviderStateChanged


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: str
    episode_id: str
    target: Target
    policy_version: str


class Broker:
    ALLOWED = {
        "gmail": {"quarantine"},
        "stripe": {"cancel"},
        "twilio": {"end"},
        "telegram": {"delete", "ban"},
        "browserbase": {"release"},
    }

    def __init__(self, store: EpisodeStore, adapter: ProviderAdapter, *, lease_guard=None):
        self.store = store
        self.adapter = adapter
        self.lease_guard = lease_guard

    def _resolve(self, action: Action) -> ProviderAdapter:
        # A ProviderRouter dispatches per provider; a single world/adapter is used directly.
        if hasattr(self.adapter, "for_provider"):
            return self.adapter.for_provider(action.target.provider)
        return self.adapter

    def authorize(self, action: Action):
        consent = self.store.consent(action.episode_id)
        binding = self.store.binding(action.episode_id, action.target)
        snapshot = self.store.episode_snapshot(action.episode_id)
        if (
            not binding
            or not consent
            or not snapshot
            or snapshot["state"] not in {"CONTAINING", "PARTIALLY_CONTAINED", "PREVENTION_FAILED"}
            or action.target.operation not in self.ALLOWED.get(action.target.provider, set())
            or not permits(
                consent,
                action.target.provider,
                action.target.resource_id,
                action.target.operation,
                datetime.now(timezone.utc),
            )
        ):
            raise PermissionError("Action outside authorized episode scope")
        binding["consent_snapshot"] = consent.model_dump(mode="json")
        history = self.store.consent_history(action.episode_id)
        binding["consent_grant_sequence"] = history[-1]["sequence"] if history else None
        return binding

    def validate_observation(self, action, binding, observation):
        if (
            observation.observed_at.tzinfo is None
            or not 0 <= (datetime.now(timezone.utc) - observation.observed_at).total_seconds() <= 60
        ):
            raise PermissionError("Provider observation is not fresh")
        if (
            observation.resource_id != action.target.resource_id
            or observation.provider != action.target.provider
            or observation.account_id != binding["account_id"]
        ):
            raise PermissionError("Provider observation identity mismatch")

    async def execute(self, action: Action) -> Observation:
        binding = self.authorize(action)
        action = self.store.persist_action(action)
        adapter = self._resolve(action)
        current = await asyncio.wait_for(adapter.read(action.target.resource_id), timeout=2)
        self.validate_observation(action, binding, current)
        self.store.record_observation(action.action_id, current)
        if current.state in terminal_states_for(action.target.operation) or current.state in {
            "unknown",
            "succeeded",
        }:
            return current
        binding = self.authorize(action)
        self.store.record_attempt(
            action.action_id,
            {"phase": "dispatch", "authority": binding, "policy_version": action.policy_version},
        )
        try:
            if self.lease_guard is not None:
                self.lease_guard()
            receipt = await asyncio.wait_for(adapter.act(action), timeout=2)
        except (TimeoutError, ConnectionError) as exc:
            self.store.record_attempt(
                action.action_id, {"phase": "uncertain_response", "error": type(exc).__name__}
            )
        except ProviderStateChanged:
            self.store.record_attempt(action.action_id, {"phase": "provider_state_changed"})
        except PermissionError:
            self.store.record_attempt(action.action_id, {"phase": "provider_permission_denied"})
            return Observation(
                provider=action.target.provider,
                resource_id=action.target.resource_id,
                account_id=binding["account_id"],
                state="unknown",
                level="requested",
                observed_at=datetime.now(timezone.utc),
                source="permission_denied",
            )
        else:
            self.store.record_attempt(
                action.action_id,
                {"phase": "acknowledged", "acknowledged": receipt.acknowledged},
                receipt.request_id,
            )
        try:
            result = await asyncio.wait_for(adapter.read(action.target.resource_id), timeout=2)
        except (TimeoutError, ConnectionError):
            result = Observation(
                provider=action.target.provider,
                resource_id=action.target.resource_id,
                account_id=binding["account_id"],
                state="unknown",
                level="requested",
                observed_at=datetime.now(timezone.utc),
                source="read_unavailable",
            )
        self.validate_observation(action, binding, result)
        self.store.record_observation(action.action_id, result)
        return result
