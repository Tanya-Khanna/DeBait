"""Reasoners produce a structured Assessment from current episode evidence.

Both implementations return the same `Assessment` shape, so the containment loop is
reasoner-agnostic: swapping the deterministic fixture stand-in for the budgeted
`ModelClient` changes *how* the next read and the interpretation are chosen, not the
control flow. Neither reasoner ever selects providers actions or payment targets —
that authority belongs to the deterministic policy and trusted-edge linking, so
attacker-controlled text can never widen scope.
"""

from typing import Protocol

from debait.episodes.models import Event
from debait.reasoning.assess import fixture_assessment, validate_assessment
from debait.reasoning.schema import REQUIRED_SIGNAL_KINDS, Assessment, ReadRequest

# Evidence markers that, together, justify proactive intervention (see schema.SignalKind).
REQUIRED_MARKERS = REQUIRED_SIGNAL_KINDS


class Reasoner(Protocol):
    async def assess(self, events: list[Event], *, allowed_reads: frozenset) -> Assessment: ...


def _missing_markers(assessment: Assessment) -> list[str]:
    present = {signal.kind for signal in assessment.signals}
    return sorted(REQUIRED_MARKERS - present)


def _prefer_next_read(events: list[Event], allowed_reads: frozenset) -> ReadRequest | None:
    """Choose the most useful unobserved resource: pursue a provider we have not seen yet.

    `allowed_reads` is already scoped by the loop to owner-permitted, not-yet-observed
    resources, so this only ranks among legitimate leads; it never invents a target.
    """
    if not allowed_reads:
        return None
    seen_providers = {event.provider for event in events}
    ranked = sorted(allowed_reads)
    for provider, resource_id in ranked:
        if provider not in seen_providers:
            return ReadRequest(provider=provider, resource_id=resource_id)
    provider, resource_id = ranked[0]
    return ReadRequest(provider=provider, resource_id=resource_id)


class FixtureReasoner:
    """Deterministic local stand-in for the model. Not an accuracy measurement.

    It extracts the same keyword markers as `fixture_assessment` and then, when the
    evidence is still incomplete, requests a bounded next read from the permitted
    resources — exactly the decision the model makes on the real path.
    """

    mode = "deterministic_fixture"

    async def assess(self, events: list[Event], *, allowed_reads: frozenset = frozenset()) -> Assessment:
        base = fixture_assessment(events)
        missing = _missing_markers(base)
        next_read = _prefer_next_read(events, allowed_reads) if missing else None
        assessment = Assessment(
            episode_id=base.episode_id,
            signals=base.signals,
            contradictions=base.contradictions,
            missing_evidence=missing,
            next_read=next_read,
        )
        return validate_assessment(assessment, events, allowed_reads=allowed_reads)


class ModelReasoner:
    """Wraps the budgeted, disabled-by-default `ModelClient` behind the Reasoner protocol.

    Enabling a real key + network turns the same containment loop into a fresh-model
    agent with no other changes. The model sees evidence strictly as untrusted data.
    """

    mode = "fresh_model"

    def __init__(self, client):
        self.client = client
        self.last_extraction = None

    async def assess(self, events: list[Event], *, allowed_reads: frozenset = frozenset()) -> Assessment:
        extraction = await self.client.extract(events, allowed_reads=allowed_reads)
        self.last_extraction = extraction
        return extraction.assessment
