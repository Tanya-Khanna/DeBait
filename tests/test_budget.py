from concurrent.futures import ThreadPoolExecutor

import pytest

from debait.episodes.store import EpisodeStore
from debait.reasoning.budget import Budget


def setup(tmp_path, limit=100):
    s = EpisodeStore(tmp_path / "db.sqlite")
    s.set_budget_limit(limit)
    return Budget(s)


def test_unknown_cost_keeps_reservation(tmp_path):
    b = setup(tmp_path)
    assert b.reserve("a", 80)
    b.settle("a", None)
    assert not b.reserve("b", 30)
    assert b.snapshot()["reserved_microdollars"] == 80


def test_concurrent_reservations_cannot_overspend(tmp_path):
    b = setup(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda i: b.reserve(str(i), 30), range(8)))
    assert sum(outcomes) == 3
    assert b.snapshot()["reserved_microdollars"] == 90


def test_duplicate_request_does_not_buy_another_call(tmp_path):
    b = setup(tmp_path)
    assert b.reserve("a", 80)
    assert not b.reserve("a", 80)
    b.settle("a", 20)
    assert not b.reserve("a", 80)
    assert b.reserve("b", 80)


def test_settlement_is_immutable_and_negative_cost_rejected(tmp_path):
    b = setup(tmp_path)
    b.reserve("a", 60)
    b.settle("a", 50)
    with pytest.raises(ValueError):
        b.settle("a", 0)
    with pytest.raises(ValueError):
        b.reserve("bad", -1)
    with pytest.raises(ValueError):
        b.settle("unknown", 4)


def test_overrun_is_recorded_and_stops_new_calls(tmp_path):
    b = setup(tmp_path)
    b.reserve("a", 80)
    b.settle("a", 120)
    assert b.snapshot()["spent_microdollars"] == 120
    assert not b.reserve("b", 1)
