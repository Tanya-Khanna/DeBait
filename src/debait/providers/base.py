from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from debait.protection.broker import Action


class Receipt(BaseModel):
    request_id: str
    acknowledged: bool


class Observation(BaseModel):
    provider: str
    resource_id: str
    account_id: str
    state: str
    level: str
    observed_at: datetime
    source: str
    details: dict = Field(default_factory=dict)


class ProviderAdapter(Protocol):
    async def read(self, resource_id: str) -> Observation: ...
    async def act(self, action: "Action") -> Receipt: ...


class RetryAfter(Exception):
    """Provider asked us to wait; elapsed time never expands authorization."""

    def __init__(self, seconds: float):
        import math

        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("Retry delay must be finite and nonnegative")
        self.seconds = seconds
        super().__init__("Provider rate limit")


class ProviderStateChanged(ValueError):
    """The operation was rejected because the resource changed after its pre-read."""
