from datetime import datetime, timezone

from debait.episodes.linking import payment_target
from debait.episodes.models import Edge, Event
from debait.episodes.store import EpisodeStore
from debait.protection.policy import Target


def graph(tmp_path):
    s = EpisodeStore(tmp_path / "db.sqlite")
    now = datetime.now(timezone.utc)
    for id, provider, resource in [
        ("web", "browserbase", "session1"),
        ("pay", "stripe", "pi_scam"),
        ("other", "stripe", "pi_other"),
    ]:
        s.ingest(
            Event(
                event_id=id,
                provider=provider,
                provider_event_id=id,
                episode_id="sc1",
                observed_at=now,
                received_at=now,
                payload={"resource_id": resource, "account_id": "test", "amount": 980000},
            )
        )
        if provider == "stripe":
            s.bind_resource(
                "sc1", Target(provider=provider, resource_id=resource, operation="cancel"), "test", [id]
            )
    return s


def test_equal_amount_cannot_establish_payment_origin(tmp_path):
    s = graph(tmp_path)
    assert payment_target(s, "sc1", "other") is None


def test_only_exact_observed_origin_resolves_payment(tmp_path):
    s = graph(tmp_path)
    s.add_edge(
        Edge(
            source_id="web",
            target_id="pay",
            kind="observed_payment_origin",
            confidence=1,
            provenance_event_ids=["web", "pay"],
        )
    )
    assert payment_target(s, "sc1", "pay").resource_id == "pi_scam"
    assert payment_target(s, "sc1", "other") is None


def test_inferred_or_uncertain_link_cannot_authorize_target(tmp_path):
    s = graph(tmp_path)
    s.add_edge(
        Edge(
            source_id="web",
            target_id="pay",
            kind="observed_payment_origin",
            confidence=0.5,
            provenance_event_ids=["web", "pay"],
        )
    )
    assert payment_target(s, "sc1", "pay") is None


def test_wrong_episode_cannot_reuse_a_valid_origin(tmp_path):
    s = graph(tmp_path)
    s.add_edge(
        Edge(
            source_id="web",
            target_id="pay",
            kind="observed_payment_origin",
            confidence=1,
            provenance_event_ids=["web", "pay"],
        )
    )
    assert payment_target(s, "sc2", "pay") is None
