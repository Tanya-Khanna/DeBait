from collections import Counter
from datetime import datetime, timezone

from debait.providers.base import Observation, Receipt


class FixtureWorld:
    def __init__(
        self, *, drop_response=False, client_observation=False, pi_scam_state="requires_confirmation"
    ):
        self._initial_drop_response = drop_response
        self.drop_response = drop_response
        self.client_observation = client_observation
        self._initial_states = {
            "scam_email": "inbox",
            "unrelated_email": "inbox",
            "pi_scam": pi_scam_state,
            "pi_unrelated": "requires_confirmation",
            "scam_call": "in-progress",
            "other_call": "in-progress",
            "scam_message": "present",
            "unrelated_message": "present",
            "scam_actor": "member",
            "other_actor": "member",
            "scam_browser": "active",
            "other_browser": "active",
        }
        self.states = dict(self._initial_states)
        self.providers = {
            key: (
                "gmail"
                if "email" in key
                else "stripe"
                if key.startswith("pi_")
                else "twilio"
                if "call" in key
                else "browserbase"
                if "browser" in key
                else "telegram"
            )
            for key in self.states
        }
        self.effects = Counter()
        self.applied = set()
        self.seed = 0

    def reset(self, seed: int = 0):
        if type(seed) is not int:
            raise TypeError("Fixture seed must be an integer")
        self.seed = seed
        self.states = dict(self._initial_states)
        self.effects.clear()
        self.applied.clear()
        self.drop_response = self._initial_drop_response

    def snapshot(self):
        return dict(self.states)

    async def read(self, resource_id):
        state = self.states[resource_id]
        level = "read_back"
        if "message" in resource_id and state == "removed":
            level = "client_observed" if self.client_observation else "acknowledged"
        return Observation(
            provider=self.providers[resource_id],
            resource_id=resource_id,
            account_id="test",
            state=state,
            level=level,
            observed_at=datetime.now(timezone.utc),
            source="local_fixture_client" if level == "client_observed" else "local_fixture_world",
        )

    async def act(self, action):
        id = action.target.resource_id
        operation = action.target.operation
        allowed = {
            "quarantine": ("gmail", {"inbox"}, "quarantined"),
            "cancel": ("stripe", {"requires_confirmation", "requires_capture"}, "canceled"),
            "end": ("twilio", {"in-progress"}, "completed"),
            "delete": ("telegram", {"present"}, "removed"),
            "ban": ("telegram", {"member"}, "banned"),
            "release": ("browserbase", {"active"}, "terminated"),
        }
        provider, valid, new = allowed[operation]
        if self.providers[id] != provider:
            raise PermissionError("Provider mismatch")
        if action.action_id not in self.applied:
            if self.states[id] not in valid:
                raise ValueError("Ineligible world transition")
            self.states[id] = new
            self.applied.add(action.action_id)
            self.effects[f"{provider}.{operation}:{id}"] += 1
            if self.drop_response and operation == "cancel":
                self.drop_response = False
                raise TimeoutError("Labeled local fault: successful response deliberately discarded")
        return Receipt(request_id=action.action_id, acknowledged=True)
