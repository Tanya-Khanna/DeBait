import re
from datetime import datetime, timezone
from hashlib import sha256
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from debait.episodes.models import Event
from debait.episodes.store import EpisodeStore


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: str
    value: str
    source_event_id: str
    source_start: int = Field(ge=0)
    source_end: int = Field(gt=0)
    observed_at: datetime
    claim_status: str = "attacker_supplied"


def extract_indicators(text: str, source_event_id: str) -> list[Indicator]:
    if not source_event_id or len(source_event_id) > 200:
        raise ValueError("A bounded source event ID is required")
    if len(text) > 20_000:
        raise ValueError("Indicator source text is too large")
    observed_at = datetime.now(timezone.utc)
    found: list[tuple[str, str, int, int]] = []
    for match in re.finditer(r"https?://[^\s<>\"']+", text, flags=re.IGNORECASE):
        raw = match.group(0).rstrip(".,);]")
        host = (urlsplit(raw).hostname or "").lower().rstrip(".")
        if host and len(host) <= 253:
            found.append(("domain", host, match.start(), match.start() + len(raw)))
    for match in re.finditer(r"(?<![\w@])@[A-Za-z0-9_]{3,32}\b", text):
        found.append(("payment_handle", match.group(0).lower(), match.start(), match.end()))
    for match in re.finditer(r"\b0x[a-fA-F0-9]{40}\b", text):
        found.append(("wallet", match.group(0).lower(), match.start(), match.end()))
    for match in re.finditer(
        r"\b(?:account|acct)\s*[:#]\s*([A-Z0-9][A-Z0-9-]{3,31})\b",
        text,
        flags=re.IGNORECASE,
    ):
        found.append(("account_string", match.group(1).upper(), match.start(1), match.end(1)))
    indicators = []
    seen = set()
    for kind, value, start, end in sorted(found, key=lambda item: item[2]):
        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)
        indicators.append(
            Indicator(
                kind=kind,
                value=value,
                source_event_id=source_event_id,
                source_start=start,
                source_end=end,
                observed_at=observed_at,
            )
        )
    return indicators


def attach_indicators(
    store: EpisodeStore, episode_id: str, source_event_id: str
) -> tuple[list[Indicator], list[str]]:
    source = next((event for event in store.events(episode_id) if event.event_id == source_event_id), None)
    if (
        source is None
        or source.provider != "hunter"
        or source.payload.get("direction") != "inbound"
        or source.payload.get("authority_scope") != "decoy_observation_only"
        or not isinstance(source.payload.get("text"), str)
    ):
        raise PermissionError("Indicators require an inbound controlled-decoy source")
    values = extract_indicators(source.payload["text"], source_event_id)
    event_ids = []
    for value in values:
        digest = sha256(f"{source_event_id}:{value.kind}:{value.value}".encode()).hexdigest()[:24]
        event = Event(
            event_id=f"hunter-indicator:{digest}",
            provider="hunter",
            provider_event_id=f"hunter-indicator:{digest}",
            episode_id=episode_id,
            observed_at=value.observed_at,
            received_at=datetime.now(timezone.utc),
            payload={
                **value.model_dump(mode="json"),
                "direction": "indicator",
                "authority_scope": "evidence_only",
            },
        )
        store.ingest(event)
        event_ids.append(event.event_id)
    return values, event_ids
