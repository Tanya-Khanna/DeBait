from pydantic import BaseModel, ConfigDict, Field


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
