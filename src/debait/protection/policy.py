from pydantic import BaseModel, ConfigDict, Field

from debait.episodes.models import Event
from debait.reasoning.schema import REQUIRED_SIGNAL_KINDS, Assessment

MIN_REQUIRED_SIGNAL_CONFIDENCE = 0.60
MIN_INDEPENDENT_EVENTS = 2
MIN_INDEPENDENT_PROVIDERS = 2
TRUSTED_EXTERNAL_PROVIDERS = frozenset({"gmail", "twilio", "telegram", "browserbase", "stripe"})


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    provider: str
    resource_id: str
    operation: str


class PolicyContext(BaseModel):
    phase: str
    sufficient_evidence: bool
    trusted_targets: list[Target] = Field(default_factory=list)
    consent_valid: bool
    payment_state: str | None = None


class Decision(BaseModel):
    next_state: str
    actions: list[Target]
    reason: str


class SemanticEvidenceDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    sufficient: bool
    confidence_threshold: float
    required_confidences: dict[str, float | None]
    missing_kinds: list[str]
    low_confidence_kinds: list[str]
    invalid_evidence_ids: list[str]
    independent_event_count: int
    independent_provider_count: int
    providers: list[str]
    reason: str


def assess_semantic_evidence(assessment: Assessment, events: list[Event]) -> SemanticEvidenceDecision:
    """Evaluate model claims against fixed confidence and trusted provenance rules."""
    event_index = {event.event_id: event for event in events if event.episode_id == assessment.episode_id}
    required_confidences: dict[str, float | None] = {}
    missing_kinds = []
    low_confidence_kinds = []
    invalid_evidence_ids = set()
    qualifying_events: set[tuple[str, str]] = set()

    for kind in sorted(REQUIRED_SIGNAL_KINDS):
        candidates = [signal for signal in assessment.signals if signal.kind == kind]
        highest = max((signal.confidence for signal in candidates), default=None)
        required_confidences[kind] = highest
        if highest is None:
            missing_kinds.append(kind)
            continue
        if highest < MIN_REQUIRED_SIGNAL_CONFIDENCE:
            low_confidence_kinds.append(kind)
            continue
        for signal in candidates:
            if signal.confidence < MIN_REQUIRED_SIGNAL_CONFIDENCE:
                continue
            for evidence_id in signal.evidence_ids:
                event = event_index.get(evidence_id)
                if event is None:
                    invalid_evidence_ids.add(evidence_id)
                elif event.provider in TRUSTED_EXTERNAL_PROVIDERS:
                    qualifying_events.add((event.provider, event.provider_event_id))

    providers = sorted({provider for provider, _ in qualifying_events})
    enough_diversity = (
        len(qualifying_events) >= MIN_INDEPENDENT_EVENTS and len(providers) >= MIN_INDEPENDENT_PROVIDERS
    )
    sufficient = not (missing_kinds or low_confidence_kinds or invalid_evidence_ids) and enough_diversity
    if missing_kinds:
        reason = "Required semantic signal classes are missing"
    elif low_confidence_kinds:
        reason = "Required semantic signals are below the calibrated confidence threshold"
    elif invalid_evidence_ids:
        reason = "Signal citations do not resolve to trusted episode evidence"
    elif not enough_diversity:
        reason = "Qualifying signals lack independent cross-provider corroboration"
    else:
        reason = "Required signals meet calibrated confidence and provenance diversity"
    return SemanticEvidenceDecision(
        sufficient=sufficient,
        confidence_threshold=MIN_REQUIRED_SIGNAL_CONFIDENCE,
        required_confidences=required_confidences,
        missing_kinds=missing_kinds,
        low_confidence_kinds=low_confidence_kinds,
        invalid_evidence_ids=sorted(invalid_evidence_ids),
        independent_event_count=len(qualifying_events),
        independent_provider_count=len(providers),
        providers=providers,
        reason=reason,
    )


def decide(context: PolicyContext) -> Decision:
    if context.phase in {"LEARNING", "CONTAINED"}:
        return Decision(next_state=context.phase, actions=[], reason="No protection dispatch in this phase")
    if not context.consent_valid or not context.sufficient_evidence:
        return Decision(next_state="REVIEW_REQUIRED", actions=[], reason="Evidence or authority insufficient")
    if context.payment_state == "succeeded":
        return Decision(
            next_state="PREVENTION_FAILED",
            actions=[
                t for t in context.trusted_targets if not (t.provider == "stripe" and t.operation == "cancel")
            ],
            reason="Payment already succeeded; contain remaining scoped resources",
        )
    return Decision(
        next_state="CONTAINING",
        actions=sorted(context.trusted_targets, key=lambda t: t.provider != "stripe"),
        reason="Preauthorized attack with exact resource bindings",
    )
