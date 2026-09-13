from datetime import datetime, timezone

import pytest

from debait.episodes.models import Event
from debait.reasoning.assess import validate_assessment
from debait.reasoning.schema import Assessment, Signal


def test_model_cannot_cite_nonexistent_evidence():
    now = datetime.now(timezone.utc)
    e = Event(
        event_id="e1",
        provider="telegram",
        provider_event_id="u1",
        episode_id="sc1",
        observed_at=now,
        received_at=now,
        payload={"text": "hello"},
    )
    a = Assessment(
        episode_id="sc1", signals=[Signal(kind="secrecy", evidence_ids=["invented"], confidence=0.9)]
    )
    with pytest.raises(ValueError, match="evidence"):
        validate_assessment(a, [e])


def test_unknown_extra_action_field_is_rejected():
    with pytest.raises(ValueError):
        Assessment.model_validate({"episode_id": "sc1", "actions": [{"operation": "send_money"}]})
