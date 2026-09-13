"""Follow a controlled Telegram conversation and prove one scoped delete + ban.

The bot polls getUpdates to *follow the conversation* — ingesting each observed
group message as evidence — then, on the message that carries a scam marker,
deletes it and bans its sender while protecting every other participant. Live
network is gated; identities are discovered from the real conversation, never
supplied by attacker content.
"""

import asyncio
import json
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.telegram import TelegramAdapter, TelegramConfig, member_resource, message_resource

# Deterministic scam-phrase markers used to flag the message to act on *until the
# real reasoning model is wired*. The LLM brain replaces this heuristic; for now a
# realistic scammer message needs one of these recognizable social-engineering phrases.
DEFAULT_MARKERS = (
    "safe account",
    "holding account",
    "support fee",
    "bail payment",
    "compromised",
    "verify immediately",
    "verify your account",
    "suspicious activity",
    "secure verification",
    "do not contact your bank",
)


class TelegramPollConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    timeout_seconds: float = Field(default=8, gt=0, le=15)
    maximum_response_bytes: int = Field(default=1048576, ge=4096, le=4194304)
    limit: int = Field(default=100, ge=1, le=100)


async def poll_conversation(
    token: SecretStr, *, config: TelegramPollConfig | None = None, transport=None, allow_network: bool = False
) -> list[dict]:
    """Return normalized non-bot messages the bot can currently see (getUpdates)."""
    config = config or TelegramPollConfig()
    if not allow_network and not isinstance(transport, httpx.MockTransport):
        raise PermissionError("Telegram conversation polling is disabled until explicitly enabled")
    try:
        async with (
            asyncio.timeout(config.timeout_seconds),
            httpx.AsyncClient(
                base_url=f"https://api.telegram.org/bot{token.get_secret_value()}",
                transport=transport,
                timeout=config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client,
        ):
            async with client.stream(
                "GET",
                "/getUpdates",
                params={"allowed_updates": json.dumps(["message"]), "limit": config.limit},
            ) as response:
                if response.status_code in {401, 403}:
                    raise PermissionError("Telegram denied getUpdates for this bot")
                if response.status_code < 200 or response.status_code >= 300:
                    raise ConnectionError(f"Telegram getUpdates failed with HTTP {response.status_code}")
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > config.maximum_response_bytes:
                        raise ConnectionError("Telegram getUpdates response exceeded the configured size")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise ConnectionError("Telegram getUpdates returned an error payload")
        messages = []
        for update in payload.get("result", []):
            message = update.get("message") if isinstance(update, dict) else None
            if not isinstance(message, dict):
                continue
            sender = message.get("from", {})
            chat = message.get("chat", {})
            if not isinstance(sender, dict) or not isinstance(chat, dict):
                continue
            if type(message.get("message_id")) is not int or type(sender.get("id")) is not int:
                continue
            if type(chat.get("id")) is not int or sender.get("is_bot") is True:
                continue
            messages.append(
                {
                    "chat_id": chat["id"],
                    "message_id": message["message_id"],
                    "from_id": sender["id"],
                    "text": str(message.get("text", "")),
                    "date": int(message.get("date", 0)),
                }
            )
        return messages
    except (PermissionError, ConnectionError):
        raise
    except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
        raise ConnectionError("Telegram getUpdates transport or response validation failed") from None


def _select_target(messages: list[dict], markers: tuple[str, ...]) -> dict:
    for message in messages:
        lowered = message["text"].lower()
        if any(marker in lowered for marker in markers):
            return message
    raise ValueError("No scam-marked message was found in the followed conversation")


async def run_telegram_smoke(
    token: SecretStr,
    *,
    run_id: str,
    markers: tuple[str, ...] = DEFAULT_MARKERS,
    transport=None,
    allow_network: bool = False,
) -> dict:
    bot_id = int(token.get_secret_value().split(":", 1)[0])
    followed = await poll_conversation(token, transport=transport, allow_network=allow_network)
    if not followed:
        raise ConnectionError("No conversation messages were visible; make the bot an admin and post first")
    scam = _select_target(followed, markers)
    chat_id = scam["chat_id"]
    attacker_id = scam["from_id"]
    conversation = [m for m in followed if m["chat_id"] == chat_id]
    protected = {m["from_id"] for m in conversation if m["from_id"] not in {attacker_id, bot_id}}
    if not protected:
        raise ValueError("A distinct owner/protected sender is required to prove the ban is scoped")

    adapter = TelegramAdapter(
        TelegramConfig(
            bot_id=bot_id,
            controlled_chat_ids=frozenset({chat_id}),
            controlled_attacker_ids=frozenset({attacker_id}),
            protected_user_ids=frozenset(protected),
        ),
        token,
        transport=transport,
        allow_network=allow_network,
    )

    # Follow the conversation: register the observed scam message as present evidence.
    msg_resource = message_resource(chat_id, scam["message_id"])
    adapter.record_message_update(
        msg_resource,
        evidence_path=f"telegram:getUpdates:{run_id}",
        observed_at=datetime.fromtimestamp(scam["date"] or 1, tz=timezone.utc),
    )

    delete = await adapter.act(
        Action(
            action_id=f"telegram-smoke-{run_id}-delete",
            episode_id=run_id,
            target=Target(provider="telegram", resource_id=msg_resource, operation="delete"),
            policy_version="telegram_live_smoke_v1",
        )
    )
    member_res = member_resource(chat_id, attacker_id)
    ban = await adapter.act(
        Action(
            action_id=f"telegram-smoke-{run_id}-ban",
            episode_id=run_id,
            target=Target(provider="telegram", resource_id=member_res, operation="ban"),
            policy_version="telegram_live_smoke_v1",
        )
    )
    after = await adapter.read(member_res)
    return {
        "run_id": run_id,
        "chat_id": chat_id,
        "followed_messages": len(conversation),
        "protected_user_ids": sorted(protected),
        "attacker_id": attacker_id,
        "scam_message_id": scam["message_id"],
        "scam_excerpt": scam["text"][:80],
        "delete_acknowledged": delete.acknowledged,
        "ban_acknowledged": ban.acknowledged,
        "attacker_member_state": after.state,
        "ban_verified": after.state == "banned",
    }
