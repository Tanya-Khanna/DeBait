import pytest

from debait.protection.broker import Action, Broker
from debait.protection.policy import Target
from debait.protection.router import ProviderRouter


class FakeAdapter:
    def __init__(self, name):
        self.name = name
        self.acted = []

    async def read(self, resource_id):
        return (self.name, resource_id)

    async def act(self, action):
        self.acted.append(action.target.provider)
        return self.name


def _action(provider):
    return Action(
        action_id="a",
        episode_id="e",
        policy_version="v",
        target=Target(provider=provider, resource_id="r", operation="op"),
    )


def test_router_routes_each_provider_to_its_adapter():
    g, s = FakeAdapter("gmail"), FakeAdapter("stripe")
    router = ProviderRouter({"gmail": g, "stripe": s})
    assert router.for_provider("gmail") is g
    assert router.for_provider("stripe") is s
    assert router.providers() == frozenset({"gmail", "stripe"})


def test_router_refuses_unregistered_provider():
    router = ProviderRouter({"gmail": FakeAdapter("gmail")})
    with pytest.raises(PermissionError):
        router.for_provider("twilio")


def test_empty_router_is_rejected():
    with pytest.raises(ValueError):
        ProviderRouter({})


def test_broker_resolves_adapter_per_action_via_router():
    g, s = FakeAdapter("gmail"), FakeAdapter("stripe")
    broker = Broker(None, ProviderRouter({"gmail": g, "stripe": s}))
    assert broker._resolve(_action("gmail")) is g
    assert broker._resolve(_action("stripe")) is s


def test_broker_uses_single_world_adapter_directly():
    world = FakeAdapter("world")  # e.g. FixtureWorld: no for_provider
    broker = Broker(None, world)
    assert broker._resolve(_action("gmail")) is world
    assert broker._resolve(_action("stripe")) is world


@pytest.mark.asyncio
async def test_router_act_dispatches_to_the_right_adapter():
    g, s = FakeAdapter("gmail"), FakeAdapter("stripe")
    router = ProviderRouter({"gmail": g, "stripe": s})
    assert await router.act(_action("stripe")) == "stripe"
    assert s.acted == ["stripe"] and g.acted == []


@pytest.mark.asyncio
async def test_router_read_is_provider_aware_even_when_resource_ids_match():
    gmail, stripe = FakeAdapter("gmail"), FakeAdapter("stripe")
    router = ProviderRouter({"gmail": gmail, "stripe": stripe})

    assert await router.read("gmail", "shared") == ("gmail", "shared")
    assert await router.read("stripe", "shared") == ("stripe", "shared")


@pytest.mark.asyncio
async def test_router_unknown_provider_read_fails_closed():
    router = ProviderRouter({"gmail": FakeAdapter("gmail")})

    with pytest.raises(PermissionError, match="No adapter"):
        await router.read("stripe", "shared")
