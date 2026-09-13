from debait.testing.world import FixtureWorld


def test_world_reset_is_reproducible_and_clears_effects():
    world = FixtureWorld()
    world.states["pi_scam"] = "canceled"
    world.effects["stripe.cancel:pi_scam"] = 1
    world.applied.add("a1")

    world.reset(seed=7)
    first = world.snapshot()
    world.states["pi_scam"] = "canceled"
    world.reset(seed=7)

    assert world.snapshot() == first
    assert first["pi_scam"] == "requires_confirmation"
    assert world.effects == {}
    assert world.applied == set()
