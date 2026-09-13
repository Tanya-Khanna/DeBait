from debait.episodes.models import Event
from debait.reasoning.schema import Assessment, Signal


def validate_assessment(
    assessment: Assessment, events: list[Event], *, allowed_reads=frozenset()
) -> Assessment:
    if not events or any(e.episode_id != assessment.episode_id for e in events):
        raise ValueError("Assessment must describe the exact supplied episode")
    if (
        assessment.next_read
        and (assessment.next_read.provider, assessment.next_read.resource_id) not in allowed_reads
    ):
        raise ValueError("Requested read is outside authorized resources")
    ids = {e.event_id for e in events if e.episode_id == assessment.episode_id}
    if not ids or any(not set(s.evidence_ids) <= ids for s in assessment.signals):
        raise ValueError("Assessment references unknown or cross-episode evidence")
    return assessment


def fixture_assessment(events: list[Event]) -> Assessment:
    """Deterministic local baseline, explicitly not an LLM or accuracy measurement."""
    signals = []
    # Canonical marker tokens across the pretext categories (bank, investment,
    # tech support, fake emergency). Kept as three stable kinds; only the phrase
    # vocabulary generalizes. This is a deterministic stand-in, not an accuracy claim.
    markers = {
        "bank_claim": ["bank fraud", "investment desk", "microsoft security", "detention officer"],
        "secrecy": [
            "don't contact your bank",
            "keep this opportunity confidential",
            "do not tell anyone your screen",
            "do not call other family",
        ],
        "payment_coercion": ["safe account", "holding account", "support fee", "bail payment"],
    }
    for event in events:
        text = str(event.payload.get("text", "")).lower()
        for kind, phrases in markers.items():
            if any(p in text for p in phrases):
                signals.append(Signal(kind=kind, evidence_ids=[event.event_id], confidence=1))
    return validate_assessment(Assessment(episode_id=events[0].episode_id, signals=signals), events)
