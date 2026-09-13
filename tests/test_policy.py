from debait.protection.policy import PolicyContext, Target, decide


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
