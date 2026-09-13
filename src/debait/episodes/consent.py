from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class Consent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    episode_id: str
    scope: frozenset[tuple[str, str, str]]
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("Consent expiry requires timezone")
        return v


def permits(consent: Consent, provider: str, resource_id: str, operation: str, now: datetime) -> bool:
    return now < consent.expires_at and (provider, resource_id, operation) in consent.scope
