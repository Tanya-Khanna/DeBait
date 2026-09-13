import sqlite3
from datetime import datetime, timezone

import pytest

from debait.episodes.models import Edge, Event
from debait.episodes.store import EpisodeStore


def event(id="e1", episode="sc1", provider_id="u1"):
    now = datetime.now(timezone.utc)
    return Event(
        event_id=id,
        provider="telegram",
        provider_event_id=provider_id,
        episode_id=episode,
        observed_at=now,
        received_at=now,
        payload={"text": "Case 7"},
    )


def test_dedup_survives_restart(tmp_path):
    path = tmp_path / "db.sqlite"
    assert EpisodeStore(path).ingest(event())
    assert not EpisodeStore(path).ingest(event())
    assert len(EpisodeStore(path).events("sc1")) == 1


def test_source_identity_cannot_be_reassigned_to_another_episode(tmp_path):
    s = EpisodeStore(tmp_path / "db.sqlite")
    s.ingest(event())
    with pytest.raises(ValueError, match="identity conflict"):
        s.ingest(event("e2", "sc2"))
    assert s.events("sc2") == []


def test_same_source_replacement_is_not_silently_accepted(tmp_path):
    s = EpisodeStore(tmp_path / "db.sqlite")
    s.ingest(event())
    other = event().model_copy(update={"payload": {"text": "replaced"}})
    with pytest.raises(ValueError, match="identity conflict"):
        s.ingest(other)


def test_edges_keep_inference_and_cannot_cross_episodes(tmp_path):
    s = EpisodeStore(tmp_path / "db.sqlite")
    s.ingest(event())
    s.ingest(event("e2", "sc1", "u2"))
    s.ingest(event("e3", "sc2", "u3"))
    s.add_edge(
        Edge(
            source_id="e1", target_id="e2", kind="inferred_actor", confidence=0.5, provenance_event_ids=["e1"]
        )
    )
    assert s.edges("sc1")[0].confidence == 0.5
    with pytest.raises(ValueError, match="same episode"):
        s.add_edge(
            Edge(
                source_id="e1",
                target_id="e3",
                kind="observed_navigation",
                confidence=1,
                provenance_event_ids=["e1"],
            )
        )


def test_database_rejects_fact_rewrite(tmp_path):
    path = tmp_path / "db.sqlite"
    EpisodeStore(path).ingest(event())
    with sqlite3.connect(path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE events SET payload='{}'")


def test_bad_timestamps_and_oversize_evidence_are_rejected():
    with pytest.raises(ValueError):
        event().model_copy().model_validate({**event().model_dump(), "observed_at": datetime.now()})
    with pytest.raises(ValueError):
        Event.model_validate({**event().model_dump(), "payload": {"text": "a" * 70000}})
