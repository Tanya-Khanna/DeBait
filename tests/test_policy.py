from datetime import datetime, timezone

from debait.episodes.models import Event
from debait.protection.policy import PolicyContext, Target, assess_semantic_evidence, decide
from debait.reasoning.schema import Assessment, Signal


def evidence(event_id, provider, *, provider_event_id=None):
    return Event(
        event_id=event_id,
        provider=provider,
        provider_event_id=provider_event_id or event_id,
        episode_id="sc1",
        observed_at=datetime.now(timezone.utc),
        received_at=datetime.now(timezone.utc),
        payload={"text": "untrusted evidence"},
    )


def assessment(*signals):
    return Assessment(episode_id="sc1", signals=list(signals))


def ctx(**changes):
    return PolicyContext(
        phase="HIGH_RISK",
        sufficient_evidence=True,
        consent_valid=True,
        trusted_targets=[Target(provider="twilio", resource_id="CA_scam", operation="end")],
        **changes,
    )


def test_protection_starts_before_a_payment_exists():
    result = decide(ctx(payment_state=None))
    assert result.next_state == "CONTAINING"
    assert result.actions[0].resource_id == "CA_scam"


def test_ambiguous_evidence_requires_review():
    c = ctx(payment_state=None)
    c.sufficient_evidence = False
    assert decide(c).actions == []
    assert decide(c).next_state == "REVIEW_REQUIRED"


def test_already_succeeded_payment_is_not_a_prevention_win():
    c = ctx(payment_state="succeeded")
    c.trusted_targets.append(Target(provider="stripe", resource_id="pi_scam", operation="cancel"))
    d = decide(c)
    assert d.next_state == "PREVENTION_FAILED"
    assert all(t.operation != "cancel" for t in d.actions)


def test_learning_phase_cannot_dispatch_payment_actions():
    c = ctx(payment_state="requires_confirmation")
    c.phase = "LEARNING"
    assert decide(c).actions == []


def test_low_confidence_required_signals_cannot_authorize_intervention():
    events = [evidence("call", "twilio"), evidence("chat", "telegram"), evidence("page", "browserbase")]
    result = assess_semantic_evidence(
        assessment(
            Signal(kind="bank_claim", confidence=0.30, evidence_ids=["call"]),
            Signal(kind="secrecy", confidence=0.35, evidence_ids=["chat"]),
            Signal(kind="payment_coercion", confidence=0.25, evidence_ids=["page"]),
        ),
        events,
    )

    assert result.sufficient is False
    assert result.low_confidence_kinds == ["bank_claim", "payment_coercion", "secrecy"]


def test_high_confidence_required_signals_with_diverse_trusted_evidence_are_sufficient():
    events = [evidence("call", "twilio"), evidence("chat", "telegram"), evidence("page", "browserbase")]
    result = assess_semantic_evidence(
        assessment(
            Signal(kind="bank_claim", confidence=0.62, evidence_ids=["call"]),
            Signal(kind="secrecy", confidence=0.92, evidence_ids=["chat"]),
            Signal(kind="payment_coercion", confidence=0.93, evidence_ids=["page"]),
        ),
        events,
    )

    assert result.sufficient is True
    assert result.independent_event_count == 3
    assert result.independent_provider_count == 3


def test_one_untrusted_page_cannot_supply_all_semantic_authority():
    events = [evidence("page", "browserbase")]
    result = assess_semantic_evidence(
        assessment(
            Signal(kind="bank_claim", confidence=1.0, evidence_ids=["page"]),
            Signal(kind="secrecy", confidence=1.0, evidence_ids=["page"]),
            Signal(kind="payment_coercion", confidence=1.0, evidence_ids=["page"]),
        ),
        events,
    )

    assert result.sufficient is False
    assert result.independent_event_count == 1
    assert result.independent_provider_count == 1


def test_duplicate_representations_of_one_artifact_do_not_count_as_corroboration():
    events = [
        evidence("page-copy-1", "browserbase", provider_event_id="same-page"),
        evidence("page-copy-2", "browserbase", provider_event_id="same-page"),
    ]
    result = assess_semantic_evidence(
        assessment(
            Signal(kind="bank_claim", confidence=1.0, evidence_ids=["page-copy-1"]),
            Signal(kind="secrecy", confidence=1.0, evidence_ids=["page-copy-2"]),
            Signal(kind="payment_coercion", confidence=1.0, evidence_ids=["page-copy-1", "page-copy-2"]),
        ),
        events,
    )

    assert result.sufficient is False
    assert result.independent_event_count == 1
    assert result.independent_provider_count == 1
