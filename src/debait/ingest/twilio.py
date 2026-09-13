"""Normalize call text without inflating its transcription provenance."""

import hashlib
import re
from datetime import datetime, timezone
from uuid import uuid4

from debait.episodes.models import Event

_CALL_SID = re.compile(r"^CA[0-9a-fA-F]{32}$")
_SOURCES = frozenset({"live_transcription", "supplied_script", "recorded_transcription"})


def normalize_call(call_sid: str, text: str, transcript_source: str, episode_resolver) -> Event:
    if not _CALL_SID.fullmatch(call_sid):
        raise ValueError("Invalid Twilio Call SID")
    if transcript_source not in _SOURCES:
        raise ValueError("Unknown transcript provenance")
    if not isinstance(text, str) or not text or len(text.encode()) > 16384:
        raise ValueError("Call text is empty or exceeds the evidence limit")
    episode_id = episode_resolver(call_sid)
    if not isinstance(episode_id, str) or not episode_id:
        raise ValueError("Call has no trusted episode binding")
    now = datetime.now(timezone.utc)
    digest = hashlib.sha256(text.encode()).hexdigest()
    return Event(
        event_id=str(uuid4()),
        provider="twilio",
        provider_event_id=f"{call_sid}:{digest}",
        episode_id=episode_id,
        observed_at=now,
        received_at=now,
        payload={
            "resource_id": call_sid,
            "text": text,
            "transcript_source": transcript_source,
            "claimed_identity": "unverified",
        },
    )
