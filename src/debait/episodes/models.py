import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    event_id: str = Field(min_length=1, max_length=200)
    provider: Literal["gmail", "twilio", "telegram", "browserbase", "stripe", "driver", "hunter"]
    provider_event_id: str = Field(min_length=1, max_length=200)
    episode_id: str = Field(min_length=1, max_length=200)
    observed_at: datetime
    received_at: datetime
    payload: dict

    @field_validator("observed_at", "received_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("UTC-aware timestamp required")
        return value.astimezone(timezone.utc)

    @field_validator("payload")
    @classmethod
    def bounded(cls, value):
        if len(json.dumps(value, ensure_ascii=False).encode()) > 65536:
            raise ValueError("Evidence exceeds 64 KiB limit")
        return value


class Edge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_id: str
    target_id: str
    kind: Literal["inferred_actor", "observed_navigation", "observed_payment_origin", "channel_migration"]
    confidence: float = Field(ge=0, le=1)
    provenance_event_ids: list[str] = Field(min_length=1)
