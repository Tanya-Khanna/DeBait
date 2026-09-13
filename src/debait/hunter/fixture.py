from debait.hunter.runner import DecoyMessage


class FixtureDecoy:
    """Deterministic local decoy; never connects to a person or provider."""

    world_kind = "fixture-world"

    def __init__(self, context_id: str, actor_id: str = "controlled-attacker"):
        self.context_id = context_id
        self.actor_id = actor_id

    async def exchange(self, prompt: str) -> DecoyMessage:
        if "test payment" not in prompt:
            raise PermissionError("Fixture decoy accepts only the bounded Hunter prompt")
        return DecoyMessage(
            message_id="fixture-payment-instructions-1",
            text="Use @mule_demo or https://pay.example.test/checkout",
        )
