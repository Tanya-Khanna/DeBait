from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# The fixed intervention taxonomy. Containment requires all three of these signal
# kinds, so the schema (and the model's structured output) is constrained to exactly
# this set — a free-form string could pass validation yet never reach the threshold.
SignalKind = Literal["bank_claim", "secrecy", "payment_coercion"]
REQUIRED_SIGNAL_KINDS = frozenset({"bank_claim", "secrecy", "payment_coercion"})


class Signal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: SignalKind
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)


class ReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    resource_id: str


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    episode_id: str
    signals: list[Signal] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    next_read: ReadRequest | None = None
