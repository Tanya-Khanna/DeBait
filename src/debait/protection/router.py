"""Route each scoped action to the adapter for its provider.

The deterministic broker/worker loop is unchanged; the router lets one episode
dispatch across the real Gmail / Twilio / Telegram / Browserbase / Stripe adapters
instead of a single world object. In fixture mode the FixtureWorld stays the single
adapter (it exposes no `for_provider`, so the broker uses it directly). In live mode
the broker is handed a ProviderRouter and resolves the exact adapter per action.
"""

from debait.providers.base import ProviderAdapter


class ProviderRouter:
    def __init__(self, adapters: dict[str, ProviderAdapter]):
        if not adapters:
            raise ValueError("Provider router requires at least one adapter")
        self._adapters = dict(adapters)

    def providers(self) -> frozenset[str]:
        return frozenset(self._adapters)

    def for_provider(self, provider: str) -> ProviderAdapter:
        adapter = self._adapters.get(provider)
        if adapter is None:
            raise PermissionError(f"No adapter is registered for provider {provider!r}")
        return adapter

    async def read(self, provider: str, resource_id: str):
        return await self.for_provider(provider).read(resource_id)

    async def act(self, action):
        return await self.for_provider(action.target.provider).act(action)
